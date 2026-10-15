// Package control 是控制面 HTTP（L4，gin 唯一属主）：用户/订阅管理端点
// （设计书 §2.1，迭代①交付四个端点；支付下单与 notify 回调随③）。
//
// gin 的唯一属主：组装根（serverapp）与其余全部包保持 gin-free，依赖触达面
// 由 internal/arch 的 ExternalDeps 钉死（gin → control）。
//
// 端点（路径与字段名见设计书 §7）：
//
//	POST /users                      创建用户（明文口令经请求体进入，服务端
//	                                 立即派生 sha256/sha224 摘要存储，明文不
//	                                 落盘、不记日志、不回显）
//	GET  /users                      列表（username / status / subscription，
//	                                 绝不回显任何凭据摘要）
//	PATCH /users/{name}              停用/启用（body {"status":"active"|"disabled"}；
//	                                 只停用不删除，设计书 §1.2）
//	PUT  /users/{name}/subscription  管理员设置订阅到期（body {"expires_at":
//	                                 RFC3339}；null = 清除订阅，人工纠错通道）
//
// 错误映射：非法 body/字段 ⇒ 400；未知用户 ⇒ 404；重复用户名 / 同隧道摘要
// （同口令）冲突 ⇒ 409。仅环回监听由 config 校验层强制（无逃生口），本包的
// handler 不重复检查。
//
// 宿主形态与 internal/status.Server 逐字对齐（Bind/Serve/Close/Addr；监听
// 绑定属于组装根的构建步骤，不变量 3：Bind 失败由调用方整体回滚）。
package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/OopsOo0ps/proxy/internal/accounts"
	"github.com/gin-gonic/gin"
)

// Deps 是 New 的依赖注入：账户存储与日志。本包不 import config / logging
// （组装根注入具体值；依赖方向由 arch 守护约束）。
type Deps struct {
	// Store 是账户存储（必填）：控制面 CRUD 的唯一领域依赖。
	Store *accounts.Store
	// Logger 记录变更事件（英文消息）；nil 时静默。
	Logger *slog.Logger
}

// Server 是控制面端点的宿主：持 http.Handler（gin 引擎）并承载监听与服务
// 生命周期。并发语义与 status.Server 一致：ln 为原子快照字段（Load/Swap 访问），
// Addr 与 Close 可与 Serve 并发调用；http.Server 为每次 Serve 调用的局部值，
// 入口一次性快照后不再读取任何 s. 字段。使用契约：每个监听恰好一个 Serve
// 消费者；重新 Bind 前必须先 Close（Bind 不关闭旧监听），但无需等待旧 Serve
// 返回——热加载 cancel → Close → 重绑路径上，旧代 Serve 入口可能延迟执行，
// 其对 ln 的 Load 不会认领重绑后的新监听（入口的 ctx.Err 检查保证）。
type Server struct {
	handler http.Handler
	// ln 是监听器的原子快照；nil 表示未绑定。
	ln atomic.Pointer[net.Listener]
}

// New 组装控制面路由（gin 引擎；零副作用，绑定监听见 Bind）。deps.Store 为
// nil 时报错（控制面没有账户存储即无意义，fail-fast 于组装期）。
func New(deps Deps) (*Server, error) {
	if deps.Store == nil {
		return nil, errors.New("control: accounts store must not be nil")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	// gin 的模式是包级全局旋钮：release 模式关闭路由注册的 stderr 调试输出，
	// 生产日志保持组装根的 JSON 形态（gin 触达面收口在本包，模式归本包管）。
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())

	a := &api{store: deps.Store, logger: logger}
	engine.POST("/users", a.createUser)
	engine.GET("/users", a.listUsers)
	engine.PATCH("/users/:name", a.patchUser)
	engine.PUT("/users/:name/subscription", a.putSubscription)
	return &Server{handler: engine}, nil
}

// Bind 绑定控制面监听；addr 为空表示不启用（空操作）。成功后监听以原子快照
// 存入 ln，后续由恰好一个 Serve 消费（语义与 status.Server.Bind 一致）。
func (s *Server) Bind(addr string) error {
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("control: listen %s: %w", addr, err)
	}
	s.ln.Store(&ln)
	return nil
}

// Serve 阻塞服务直到 ctx 取消（3s 内排空在途请求）；未绑定时立即返回 nil，
// 且不启动任何协程。调用时 ctx 已取消则直接返回 ctx.Err()，同样不启动任何
// 协程、不触碰当前监听器（避免热加载 cancel → Close → 重绑窗口内旧代 Serve
// 认领新监听、随后其 Shutdown 把新监听一并关闭——status.Server 的实证语义）。
func (s *Server) Serve(ctx context.Context) error {
	if s == nil {
		return nil
	}
	lnp := s.ln.Load()
	if lnp == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ln := *lnp
	handler := s.handler
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		case <-done:
		}
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close 关闭监听（停止接受新连接）；幂等。原子 Swap 取出监听后置空快照，
// 重复调用（或与 Addr/Serve 并发）返回 nil。在途请求的排空由 Serve 的 ctx
// 关停协程负责，本方法不做 Shutdown。
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	ln := s.ln.Swap(nil)
	if ln == nil {
		return nil
	}
	return (*ln).Close()
}

// Addr 返回绑定地址；未绑定时为空串。原子读取，可与 Close/Serve 并发调用。
func (s *Server) Addr() string {
	if s == nil {
		return ""
	}
	ln := s.ln.Load()
	if ln == nil {
		return ""
	}
	return (*ln).Addr().String()
}

// —— 路由处理器（deps 的非导出载体）——

// api 是全部路由处理器共享的依赖集合。
type api struct {
	store  *accounts.Store
	logger *slog.Logger
}

// userView 是账户的 API 形态：只携带管理面词汇，绝不回显凭据（明文与
// sha256/sha224 摘要都不出控制面）。
type userView struct {
	Username     string              `json:"username"`
	Status       accounts.UserStatus `json:"status"`
	Subscription *subscriptionView   `json:"subscription,omitempty"`
}

// subscriptionView 是订阅的 API 形态；无订阅时整体省略。
type subscriptionView struct {
	ExpiresAt time.Time `json:"expires_at"`
	GrantedAt time.Time `json:"granted_at"`
}

// userViewOf 把领域快照转换为 API 形态。
func userViewOf(u accounts.User) userView {
	v := userView{Username: u.Username, Status: u.Status}
	if !u.Subscription.ExpiresAt.IsZero() {
		v.Subscription = &subscriptionView{
			ExpiresAt: u.Subscription.ExpiresAt,
			GrantedAt: u.Subscription.GrantedAt,
		}
	}
	return v
}

// errorResponse / listResponse 是响应信封。
type errorResponse struct {
	Error string `json:"error"`
}

type listResponse struct {
	Users []userView `json:"users"`
}

// createUserBody 是 POST /users 的请求体（明文凭据，仅存在于请求处理期）。
type createUserBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// createUser 创建用户：服务端立即派生 sha256（入站比对）与 sha224（隧道反查）
// 摘要交 Store 存储，明文不落盘、不记日志、不进任何响应。
func (a *api) createUser(c *gin.Context) {
	var body createUserBody
	if err := c.ShouldBindJSON(&body); err != nil {
		respondError(c, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validateCredentials(body.Username, body.Password); err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	u := accounts.User{
		Username:       body.Username,
		PasswordSHA256: hex.EncodeToString(sum256(body.Password)),
		PasswordSHA224: hex.EncodeToString(sum224(body.Password)),
		Status:         accounts.StatusActive,
	}
	if err := a.store.Create(u); err != nil {
		a.respondStoreError(c, err)
		return
	}
	a.logger.Info("user created", "username", u.Username)
	c.JSON(http.StatusCreated, userViewOf(u))
}

// listUsers 返回全部账户（插入序；不回显凭据摘要）。
func (a *api) listUsers(c *gin.Context) {
	users := a.store.List()
	views := make([]userView, 0, len(users))
	for _, u := range users {
		views = append(views, userViewOf(u))
	}
	c.JSON(http.StatusOK, listResponse{Users: views})
}

// patchUserBody 是 PATCH /users/{name} 的请求体：只停用/启用，不删除
// （设计书 §1.2：订单以用户名字符串引用账户，物理删除会制造孤儿引用）。
type patchUserBody struct {
	Status accounts.UserStatus `json:"status"`
}

// patchUser 设置账户状态（active | disabled）。
func (a *api) patchUser(c *gin.Context) {
	var body patchUserBody
	if err := c.ShouldBindJSON(&body); err != nil {
		respondError(c, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name := c.Param("name")
	if err := a.store.SetStatus(name, body.Status); err != nil {
		a.respondStoreError(c, err)
		return
	}
	u, err := a.store.Get(name)
	if err != nil {
		a.respondStoreError(c, err)
		return
	}
	a.logger.Info("user status changed", "username", u.Username, "status", u.Status)
	c.JSON(http.StatusOK, userViewOf(u))
}

// putSubscriptionBody 是 PUT /users/{name}/subscription 的请求体：expires_at
// 为 RFC3339 时刻；null（或缺省）= 清除订阅（PUT 整置语义，回到无订阅）。
type putSubscriptionBody struct {
	ExpiresAt *time.Time `json:"expires_at"`
}

// putSubscription 管理员设置订阅到期时刻（人工纠错通道，可任意设置，含过去
// 时刻 = 即刻过期语义；授予时刻由 Store 按当前时钟记录）。
func (a *api) putSubscription(c *gin.Context) {
	var body putSubscriptionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		respondError(c, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name := c.Param("name")
	expiresAt := time.Time{}
	if body.ExpiresAt != nil {
		expiresAt = *body.ExpiresAt
	}
	if err := a.store.SetSubscriptionExpiresAt(name, expiresAt); err != nil {
		a.respondStoreError(c, err)
		return
	}
	u, err := a.store.Get(name)
	if err != nil {
		a.respondStoreError(c, err)
		return
	}
	a.logger.Info("user subscription updated", "username", u.Username)
	c.JSON(http.StatusOK, userViewOf(u))
}

// respondStoreError 把领域错误映射为 HTTP 状态码：未知用户 ⇒ 404；字段形状
// 非法 ⇒ 400；其余（只读存储 / 落盘失败）为服务端故障——日志记明细，线上给
// 中性文案（不回显内部错误细节）。
func (a *api) respondStoreError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, accounts.ErrUnknownUser):
		respondError(c, http.StatusNotFound, "unknown user")
	case errors.Is(err, accounts.ErrInvalidUser):
		respondError(c, http.StatusBadRequest, err.Error())
	case errors.Is(err, accounts.ErrDuplicateUsername), errors.Is(err, accounts.ErrTunnelHashConflict):
		respondError(c, http.StatusConflict, conflictMessage(err))
	default:
		a.logger.Error("control plane mutation failed", "error", err)
		respondError(c, http.StatusInternalServerError, "internal error")
	}
}

// conflictMessage 给出 409 的可读原因（控制面仅环回，明确原因便于运维纠错）。
func conflictMessage(err error) string {
	switch {
	case errors.Is(err, accounts.ErrDuplicateUsername):
		return "username already exists"
	case errors.Is(err, accounts.ErrTunnelHashConflict):
		return "password conflicts with an existing user"
	default:
		return "user rejected"
	}
}

// respondError 输出统一 JSON 错误体。
func respondError(c *gin.Context, code int, message string) {
	c.JSON(code, errorResponse{Error: message})
}

// validateCredentials 校验明文凭据形状（镜像 internal/auth 与 config 的既有
// 规则：非空、不含 CR/LF；摘要形态校验归 Store.Create）。
func validateCredentials(username, password string) error {
	switch {
	case strings.TrimSpace(username) == "":
		return errors.New("username must not be empty")
	case strings.ContainsAny(username, "\r\n"):
		return errors.New("username must not contain CR or LF")
	case password == "":
		return errors.New("password must not be empty")
	case strings.ContainsAny(password, "\r\n"):
		return errors.New("password must not contain CR or LF")
	}
	return nil
}

// sum256 / sum224 派生凭据摘要（hex 之前的原始字节）。
func sum256(password string) []byte {
	sum := sha256.Sum256([]byte(password))
	return sum[:]
}

func sum224(password string) []byte {
	sum := sha256.Sum224([]byte(password))
	return sum[:]
}
