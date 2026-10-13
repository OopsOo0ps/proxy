// Package serverapp 组装 proxy-server（设计文档 §8 组装根）：解析配置 →
// 构建不可变运行时快照（含监听绑定）→ 原子切换 → 旧快照排空。
//
// 服务端没有另一套模型——它是“入站（trojan 隧道协议接受器）+ 直连出站”
// 的特化（§5.1）：没有 routing / ruleset / nodes。协议分派只有入站一个
// 位置（全仓唯一，§7.4）：buildInbound 按 type 分派（trojan → DecodeParams
// → 证书 / 凭据 / 伪装页在组装根封闭，凭据校验在 auth.Store 构造）。
// 出站是共享的直连拨号器（dialer.NewDirect，§5.3 directDialer）。
package serverapp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/defaults"
	"github.com/OopsOo0ps/proxy/internal/dialer"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/netutil"
	"github.com/OopsOo0ps/proxy/internal/status"
	"github.com/OopsOo0ps/proxy/internal/trojan"
	"github.com/OopsOo0ps/proxy/internal/version"
)

// KnownProtocols 是本组装根能分派的协议全集：入站 trojan，无出站侧。
var KnownProtocols = config.ProtocolSet{
	Inbounds: []string{config.TypeTrojan},
}

// —— 运行时快照 ——

// Runtime 是一次构建的全部产物（组装根的运行时快照）。构造后不可变：
// 热加载产出全新快照（证书、凭据、伪装页重建），原子替换。
type Runtime struct {
	// Inbounds 是全部入站端点（监听已绑定，服务函数就绪）。
	Inbounds []InboundServer
	// Outbound 是出站组合树根：服务端即出口，直连拨号器（§5.3）。
	Outbound core.TargetDialer
	// Telemetry 是遥测出口（L4 metrics 适配）。
	Telemetry core.Telemetry
	// Admin 是运维端点（/metrics /health /stats /log/level）。
	Admin *status.Server

	cfg *config.Config
}

// InboundServer 是构建完成的一个入站端点：协议端点就绪，监听由绑定步骤
// 接入。Serve / Close / Addr 在绑定前为空操作，绑定后即可用。
type InboundServer struct {
	// Proto 是观测口径（core.ProtoTunnel）。
	Proto string
	// Config 是入站配置快照：同端口重绑与失败恢复按它重建监听。
	Config config.Inbound
	// Listener 是已绑定的监听（TLS 层，含并发闸包装）。
	Listener net.Listener
	// Serve 阻塞服务直到 ctx 取消：停止接受新连接，存量连接按排空语义收尾。
	Serve func(ctx context.Context) error
	// Close 关闭监听（停止接受新连接）；幂等，不影响存量连接。
	Close func()
	// Addr 返回绑定后的实际监听地址；未绑定时为空串。
	Addr func() string

	bind func(limiter *connlimit.Limiter, previous string) (inboundBound, error)

	// certExpiredAt 是该入站证书的过期时刻（零值 = 未知；/health 依赖检查）。
	certExpiredAt time.Time
}

func newInboundServer(ic config.Inbound) InboundServer {
	is := InboundServer{Proto: core.ProtoTunnel, Config: ic}
	is.Serve = func(context.Context) error { return nil }
	is.Close = func() {}
	is.Addr = func() string { return "" }
	return is
}

// inboundBound 是一次成功绑定产生的运行期产物。
type inboundBound struct {
	listener net.Listener
	serve    func(ctx context.Context) error
	close    func()
	addr     func() string
}

// apply 把绑定产物回填到端点（绑定后 Serve / Close / Addr 即可用）。
func (is *InboundServer) apply(b inboundBound) {
	is.Listener = b.listener
	is.Serve = b.serve
	is.Close = b.close
	is.Addr = b.addr
}

// Close 关闭监听（幂等）：G4 守护测试与构建失败清理路径使用。
func (r *Runtime) Close() {
	r.closeListeners()
}

// closeListeners 关闭全部监听（入站 + 运维端点；幂等）。
func (r *Runtime) closeListeners() {
	for i := range r.Inbounds {
		r.Inbounds[i].Close()
	}
	_ = r.Admin.Close()
}

// resolvedAddrOf 返回与 ic 同（type, listen）的旧入站已解析地址：
// 重载绑定时的端口稳定提示（端口 0 的配置在重载后保持原端口）。
func (r *Runtime) resolvedAddrOf(ic config.Inbound) string {
	for i := range r.Inbounds {
		old := &r.Inbounds[i]
		if old.Config.Type == ic.Type && old.Config.Listen == ic.Listen {
			return old.Addr()
		}
	}
	return ""
}

// —— 构建依赖 ——

// BuildOptions 是包级 Build 的组装依赖（G4 示例配置守护测试与直接构造
// 场景使用；常驻服务经 New 构造）。
type BuildOptions struct {
	// Logger 记录构建期告警与隧道日志；nil 时静默。
	Logger *slog.Logger
	// Metrics 是遥测出口；nil 时使用空指标。
	Metrics *metrics.Metrics
	// Limiter 是进程级并发闸；nil 时不限流。
	Limiter *connlimit.Limiter
	// Version 出现在 /stats。
	Version string
	// LogCtrl 是运行时可调日志控制器；nil 时 /log/level 端点不可用。
	LogCtrl *logging.Control
}

// builder 承载一次组装的全部依赖；App 持有同一 builder 覆盖完整生命周期。
type builder struct {
	logger  *slog.Logger
	metrics *metrics.Metrics
	limiter *connlimit.Limiter
	version string
	start   time.Time
	logCtrl *logging.Control
	live    *atomic.Pointer[Runtime]

	rejects rejectThrottle
}

func newBuilder(opts BuildOptions, live *atomic.Pointer[Runtime]) builder {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	m := opts.Metrics
	if m == nil {
		m = metrics.New(nil)
	}
	return builder{
		logger:  logger,
		metrics: m,
		limiter: opts.Limiter,
		version: opts.Version,
		start:   time.Now(),
		logCtrl: opts.LogCtrl,
		live:    live,
	}
}

// —— 组装（除监听绑定外零副作用）——

// assemble 依据配置构建完整运行时（不绑定监听）：每入站一次证书加载、
// 凭据重建与伪装页读取。任何失败都不产生外部副作用。
func (b *builder) assemble(cfg *config.Config) (*Runtime, error) {
	rt := &Runtime{cfg: cfg, Telemetry: b.metrics}
	// 服务端即出口：出站组合树就是共享的直连拨号器（§5.3 directDialer），
	// 单请求期限由 trojan 服务端按当前快照收敛。
	rt.Outbound = dialer.NewDirect(cfg.Timeouts.EffectiveDial())
	for i := range cfg.Inbounds {
		is, err := b.buildInbound(&cfg.Inbounds[i], rt)
		if err != nil {
			return nil, err
		}
		rt.Inbounds = append(rt.Inbounds, is)
	}
	rt.Admin = status.NewServer(status.ServerOptions{
		Version:  b.version,
		Start:    b.start,
		Checks:   b.healthChecks(),
		Runtime:  b.runtimeStats,
		Metrics:  b.metrics.Handler(),
		LogLevel: b.logLevelHandler(),
	})
	return rt, nil
}

// bindRuntime 绑定运行时的全部监听（入站 + 运维端点）。previous 非 nil 时，
// 与旧入站同（type, listen）的端点沿用其已解析地址（端口 0 的配置在重载后
// 保持原端口）。任何失败关闭已绑定的一切并返回错误（不变量 3）。
func (b *builder) bindRuntime(rt *Runtime, previous *Runtime) error {
	for i := range rt.Inbounds {
		hint := ""
		if previous != nil {
			hint = previous.resolvedAddrOf(rt.Inbounds[i].Config)
		}
		bound, err := rt.Inbounds[i].bind(b.limiter, hint)
		if err != nil {
			rt.closeListeners()
			return err
		}
		rt.Inbounds[i].apply(bound)
	}
	if err := rt.Admin.Bind(rt.cfg.API.Listen); err != nil {
		rt.closeListeners()
		return err
	}
	if addr := rt.cfg.API.Listen; addr != "" && !config.IsLoopbackListen(addr) {
		b.logger.Warn("ops endpoints are bound to a non-loopback address; keep them behind a firewall and note PUT /log/level stays loopback-only", "listen", addr)
	}
	return nil
}

// buildInbound 是入站协议分派点（全仓唯一）：trojan 服务端凭据只存
// SHA-224 摘要（auth.Store 构造时派生），协议语义校验在凭据构造处。
// 返回的端点尚未绑定监听（绑定属构建步骤，不变量 3）。
func (b *builder) buildInbound(ic *config.Inbound, rt *Runtime) (InboundServer, error) {
	if ic.Type != config.TypeTrojan {
		return InboundServer{}, fmt.Errorf("unknown inbound type %q", ic.Type)
	}
	var params trojan.ServerParams
	if err := config.DecodeParams(ic.Params, &params); err != nil {
		return InboundServer{}, fmt.Errorf("inbound %q: decode trojan params: %w", ic.Listen, err)
	}
	cert, err := tls.LoadX509KeyPair(params.CertFile, params.KeyFile)
	if err != nil {
		return InboundServer{}, fmt.Errorf("trojan inbound %s: load tls key pair: %w", ic.Listen, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return InboundServer{}, fmt.Errorf("trojan inbound %s: parse tls certificate: %w", ic.Listen, err)
	}
	users := make([]auth.User, 0, len(params.Users))
	for _, u := range params.Users {
		users = append(users, auth.User{Username: u.Username, Password: u.Password})
	}
	store, err := auth.NewStore(users)
	if err != nil {
		return InboundServer{}, fmt.Errorf("trojan inbound %s: %w", ic.Listen, err)
	}
	decoy := trojan.DefaultDecoyPage
	if params.DecoyFile != "" {
		data, err := os.ReadFile(params.DecoyFile)
		if err != nil {
			return InboundServer{}, fmt.Errorf("trojan inbound %s: read decoy file: %w", ic.Listen, err)
		}
		if len(data) == 0 {
			return InboundServer{}, fmt.Errorf("trojan inbound %s: decoy file is empty", ic.Listen)
		}
		decoy = data
	}

	live := liveView{live: b.live, verifier: store, decoy: decoy}
	srv := &trojan.Server{
		Dial:      rt.Outbound,
		Live:      live,
		Logger:    b.logger,
		Telemetry: b.metrics,
	}
	is := newInboundServer(*ic)
	is.certExpiredAt = leaf.NotAfter
	is.bind = func(limiter *connlimit.Limiter, previous string) (inboundBound, error) {
		ln, err := net.Listen("tcp", bindAddr(ic.Listen, previous))
		if err != nil {
			return inboundBound{}, fmt.Errorf("serverapp: listen trojan %s: %w", ic.Listen, err)
		}
		wrapped := connlimit.WrapListener(ln, limiter, func(conn net.Conn) {
			// 过载拒绝也是一次 accept 后的终态：先开后拒，保持 active 口径
			// 平衡（active = ConnOpened − (ConnDone+ConnRejected)）。
			b.metrics.ConnOpened(core.ProtoTunnel)
			b.metrics.ConnRejected(core.ProtoTunnel, core.ResultOverload)
			b.logTunnelReject(conn)
			_ = conn.Close()
		})
		tlsLn := tls.NewListener(wrapped, &tls.Config{
			// GetCertificate 每次握手读取本端点凭据：证书文件热重载即刻生效
			//（凭据重建发生在快照构建，此处只引用已构建的证书）。
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return &cert, nil
			},
			MinVersion: tls.VersionTLS12,
		})
		return inboundBound{
			listener: tlsLn,
			serve:    func(ctx context.Context) error { return srv.Serve(ctx, tlsLn) },
			close:    func() { _ = ln.Close() },
			addr:     func() string { return tlsLn.Addr().String() },
		}, nil
	}
	return is, nil
}

// bindAddr 返回实际绑定的地址：端口 0（自动分配）的配置沿用 previous 的
// 已解析地址（重载不改变端口）；显式端口按配置原样绑定。
func bindAddr(configured, previous string) string {
	if previous == "" {
		return configured
	}
	if _, port, err := net.SplitHostPort(configured); err == nil && port == "0" {
		return previous
	}
	return configured
}

// —— 热加载视图（运行期热更路径）——

// liveView 是 trojan 服务端的热加载视图：凭据与伪装页锚定构建该入站时的
// 快照（生效边界 = 新握手），超时读当前快照。
type liveView struct {
	live     *atomic.Pointer[Runtime]
	verifier *auth.Store
	decoy    []byte
}

func (l liveView) Verifier() trojan.Verifier { return l.verifier }
func (l liveView) Decoy() []byte             { return l.decoy }

func (l liveView) handshakeTimeout() time.Duration {
	if rt := l.live.Load(); rt != nil {
		return rt.cfg.Timeouts.EffectiveHandshake()
	}
	return defaults.HandshakeTimeout
}

func (l liveView) DialTimeout() time.Duration {
	if rt := l.live.Load(); rt != nil {
		return rt.cfg.Timeouts.EffectiveDial()
	}
	return defaults.DialTimeout
}

func (l liveView) IdleTimeout() time.Duration {
	if rt := l.live.Load(); rt != nil {
		return rt.cfg.Timeouts.EffectiveIdle()
	}
	return defaults.IdleTimeout
}

func (l liveView) ShutdownTimeout() time.Duration {
	if rt := l.live.Load(); rt != nil {
		return rt.cfg.Timeouts.EffectiveShutdown()
	}
	return defaults.DrainTimeout
}

// HandshakeTimeout 实现 trojan.LivePolicy。
func (l liveView) HandshakeTimeout() time.Duration { return l.handshakeTimeout() }

// 编译期断言：消费方接口与适配器失配（增删方法）会直接编译失败。
var _ trojan.LivePolicy = liveView{}

// —— 可观测性接缝 ——

func (b *builder) logLevelHandler() http.Handler {
	if b.logCtrl == nil {
		return nil
	}
	return logging.LevelHandler(b.logger, b.logCtrl.LevelVar())
}

// healthChecks 返回依赖健康检查：TLS 证书在运行中过期时依赖不可用。
func (b *builder) healthChecks() []func() error {
	return []func() error{func() error {
		rt := b.live.Load()
		if rt == nil {
			return nil
		}
		for i := range rt.Inbounds {
			if !rt.Inbounds[i].certExpiredAt.IsZero() && !time.Now().Before(rt.Inbounds[i].certExpiredAt) {
				return errors.New("tls certificate expired")
			}
		}
		return nil
	}}
}

// runtimeStats 组装 /stats 快照：隧道活跃连接数。
func (b *builder) runtimeStats() status.Runtime {
	tunnel := b.metrics.ActiveByProto()[core.ProtoTunnel]
	rt := status.Runtime{
		Connections: status.Connections{Tunnel: tunnel, Total: tunnel},
	}
	if b.limiter != nil {
		rt.Limit = &status.Limit{
			MaxConnections: b.limiter.Max(),
			Current:        b.limiter.Active(),
			Rejected:       b.limiter.Rejected(),
		}
	}
	return rt
}

// rejectThrottle 限制隧道侧超限拒绝日志的频率（每秒最多一条，避免过载时
// 刷日志）；builder 跨组装共享（进程级节流）。
type rejectThrottle struct {
	mu sync.Mutex
	at time.Time
}

func (t *rejectThrottle) allow(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.at) < time.Second {
		return false
	}
	t.at = now
	return true
}

// logTunnelReject 记录一次隧道侧超限拒绝（每秒最多一条，避免过载时刷日志）。
func (b *builder) logTunnelReject(conn net.Conn) {
	if !b.rejects.allow(time.Now()) {
		return
	}
	b.logger.Warn("connection limit reached; rejecting tunnel connection",
		"remote", netutil.RemoteIP(conn.RemoteAddr()))
}

// —— App：生命周期与重载流水线 ——

// generation 是一次快照上线后的服务代际：代际 ctx 取消触发该代际全部入站
// 与运维端点的既有 drain/force 语义（session 机械）。每个代际持有独立的
// 服务协程计数与 done 信号：Serve 等待“当前代际”退出，重载以新代际整体
// 替换——跨代际共享一个 WaitGroup 会在新旧交替的间隙归零，使 Wait 提前
// 返回（Add-after-Wait 竞态），这是按代际计数的根本原因。
type generation struct {
	rt     *Runtime
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	done   chan struct{} // 全部服务协程退出后关闭
}

// App 是组装完成的 proxy-server 实例。
// 生命周期：New（构建快照并绑定监听）→ Serve（阻塞服务直到 ctx 取消）。
// 配置热加载见 Reload：先完整构建新快照，全部成功后原子切换并排空旧快照；
// 任何失败都保持旧配置在原端口继续服务。
type App struct {
	b    builder
	live atomic.Pointer[Runtime]
	gen  atomic.Pointer[generation]

	reloadMu  sync.Mutex
	closing   atomic.Bool
	serving   atomic.Bool
	serveCtx  context.Context // Serve 启动后写入；重载以此为父 ctx
	appCancel context.CancelFunc

	errMu    sync.Mutex
	firstErr error
}

// New 校验并组装应用：构建完整运行时快照并绑定全部监听（不变量 3：
// 任何失败关闭已打开的一切并返回错误）。logCtrl 是运行时可调日志控制器
// （可为 nil，此时 /log/level 端点不可用）。
func New(cfg *config.Config, logger *slog.Logger, logCtrl *logging.Control) (*App, error) {
	app := &App{}
	app.b = newBuilder(BuildOptions{
		Logger:  logger,
		Metrics: metrics.New([]string{core.ProtoTunnel}),
		Limiter: connlimit.New(cfg.Limits.EffectiveMaxConnections()),
		Version: version.Get().Version,
		LogCtrl: logCtrl,
	}, &app.live)

	rt, err := app.b.assemble(cfg)
	if err != nil {
		return nil, err
	}
	if err := app.b.bindRuntime(rt, nil); err != nil {
		rt.closeListeners()
		return nil, err
	}
	app.live.Store(rt)
	return app, nil
}

// Build 依据配置构建完整运行时快照（含监听绑定）：除绑定外无副作用；
// 任何失败关闭已绑定的一切并返回错误（不变量 3）。供 G4 示例配置守护
// 测试与直接构造场景使用；常驻服务请使用 New。
func Build(cfg *config.Config, opts BuildOptions) (*Runtime, error) {
	var live atomic.Pointer[Runtime]
	b := newBuilder(opts, &live)
	rt, err := b.assemble(cfg)
	if err != nil {
		return nil, err
	}
	if err := b.bindRuntime(rt, nil); err != nil {
		rt.closeListeners()
		return nil, err
	}
	live.Store(rt)
	return rt, nil
}

// Serve 阻塞服务直到 ctx 取消或任一监听出错；返回前完成优雅关停
// （存量隧道按排空期限收尾）。重载产出的新代际在切换时即上线。
func (a *App) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	a.reloadMu.Lock()
	a.serveCtx = ctx
	a.appCancel = cancel
	gen := a.gen.Load()
	if gen == nil {
		gen = a.startGeneration(a.live.Load())
	}
	a.serving.Store(true)
	a.reloadMu.Unlock()
	defer func() {
		a.reloadMu.Lock()
		a.serving.Store(false)
		a.closing.Store(true)
		a.reloadMu.Unlock()
	}()

	go func() {
		<-ctx.Done()
		if g := a.gen.Load(); g != nil {
			g.cancel()
		}
	}()

	for {
		<-gen.done
		// 当前代际退出：应用级关停、被重载替换、或服务协程全部意外结束。
		if ctx.Err() != nil {
			a.reloadMu.Lock()
			latest := a.gen.Load()
			a.reloadMu.Unlock()
			if latest != nil && latest != gen {
				<-latest.done
			}
			return a.firstError()
		}
		a.reloadMu.Lock()
		latest := a.gen.Load()
		a.reloadMu.Unlock()
		if latest == gen {
			return a.firstError()
		}
		gen = latest
	}
}

// startGeneration 让快照上线：spawn 全部服务协程。必须在 reloadMu 持有时调用。
func (a *App) startGeneration(rt *Runtime) *generation {
	parent := a.serveCtx
	if parent == nil {
		parent = context.Background()
	}
	gctx, cancel := context.WithCancel(parent)
	gen := &generation{rt: rt, ctx: gctx, cancel: cancel, done: make(chan struct{})}
	gen.wg.Add(len(rt.Inbounds) + 1) // 入站 + 运维端点（先计数后 spawn）
	for i := range rt.Inbounds {
		is := &rt.Inbounds[i]
		go func() {
			defer gen.wg.Done()
			if err := is.Serve(gctx); err != nil && gctx.Err() == nil && parent.Err() == nil {
				a.fail(fmt.Errorf("serverapp: inbound %s: %w", is.Config.Type, err))
			}
		}()
	}
	go func() {
		defer gen.wg.Done()
		if err := rt.Admin.Serve(gctx); err != nil && gctx.Err() == nil && parent.Err() == nil {
			a.fail(fmt.Errorf("serverapp: admin endpoint: %w", err))
		}
	}()
	go func() {
		gen.wg.Wait()
		close(gen.done)
	}()
	a.gen.Store(gen)
	return gen
}

// fail 记录首个致命服务错误并触发应用级关停（全部代际随之排空）。
func (a *App) fail(err error) {
	a.errMu.Lock()
	if a.firstErr == nil {
		a.firstErr = err
	}
	a.errMu.Unlock()
	if a.appCancel != nil {
		a.appCancel()
	}
}

func (a *App) firstError() error {
	a.errMu.Lock()
	defer a.errMu.Unlock()
	return a.firstErr
}

// TunnelAddr 返回首个 trojan 入站的实际监听地址。
func (a *App) TunnelAddr() string { return a.inboundAddr() }

func (a *App) inboundAddr() string {
	if rt := a.live.Load(); rt != nil {
		for i := range rt.Inbounds {
			if rt.Inbounds[i].Config.Type == config.TypeTrojan {
				return rt.Inbounds[i].Addr()
			}
		}
	}
	return ""
}

// MetricsAddr 返回运维端点实际监听地址（未启用时为空）。
func (a *App) MetricsAddr() string {
	if rt := a.live.Load(); rt != nil {
		return rt.Admin.Addr()
	}
	return ""
}

// Reload 应用一份新配置（重载流水线）：先完整构建新运行时（证书重载、
// 凭据重建、伪装页重读），全部成功后原子切换（先停旧监听再绑新监听，
// 失败回滚恢复旧服务，见 switchTo）；任何失败都返回错误并保持旧配置
// 在原端口继续服务。
//
// 生效边界为“新握手”：已在转发的隧道继续使用旧快照收尾；新握手立即
// 使用新凭据与新证书。
func (a *App) Reload(next *config.Config) (err error) {
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()
	if a.closing.Load() || (a.serveCtx != nil && a.serveCtx.Err() != nil) || a.shuttingDown() {
		return errors.New("serverapp: shutting down; reload ignored")
	}

	cur := a.live.Load()
	result := metrics.ReloadError
	defer func() { a.b.metrics.ConfigReload(result) }()

	rt, err := a.b.assemble(next)
	if err != nil {
		return fmt.Errorf("serverapp: build new configuration: %w", err)
	}
	if err := a.switchTo(cur, rt); err != nil {
		return err
	}

	a.b.limiter.SetMax(next.Limits.EffectiveMaxConnections())
	if a.b.logCtrl != nil {
		a.b.logCtrl.SetLevel(next.Log.Level)
		a.b.logCtrl.SetFormat(next.Log.Format)
	}
	result = metrics.ReloadSuccess
	users := 0
	for i := range next.Inbounds {
		var params trojan.ServerParams
		if err := config.DecodeParams(next.Inbounds[i].Params, &params); err == nil {
			users += len(params.Users)
		}
	}
	a.b.logger.Info("configuration reloaded",
		"inbounds", len(next.Inbounds),
		"users", users,
		"max_connections", next.Limits.EffectiveMaxConnections(),
	)
	return nil
}

// shuttingDown 报告当前代际是否已进入关停（排空中拒绝重载）。
func (a *App) shuttingDown() bool {
	if gen := a.gen.Load(); gen != nil {
		return gen.ctx.Err() != nil
	}
	return false
}

// switchTo 原子切换运行时（reloadMu 持有）：停旧 → 绑新（失败回滚恢复
// 旧服务）→ 提交。语义与 clientapp 相同，见其注释。
func (a *App) switchTo(cur, next *Runtime) error {
	if gen := a.gen.Load(); gen != nil && gen.rt == cur {
		gen.cancel()
	}
	cur.closeListeners()

	if err := a.b.bindRuntime(next, cur); err != nil {
		next.closeListeners()
		if rerr := a.restore(cur); rerr != nil {
			a.b.logger.Error("reload rollback failed; previous listeners could not be rebound", "error", rerr)
			return fmt.Errorf("serverapp: bind new configuration: %v; rollback failed: %w", err, rerr)
		}
		return fmt.Errorf("serverapp: bind new configuration: %w", err)
	}

	a.live.Store(next)
	if a.serving.Load() {
		a.startGeneration(next)
	}
	return nil
}

// restore 在绑定失败后恢复旧配置服务：用旧运行时保存的入站配置重建监听
// 并重新上线。
func (a *App) restore(cur *Runtime) error {
	if err := a.b.bindRuntime(cur, nil); err != nil {
		return err
	}
	if a.serving.Load() {
		restored := *cur
		a.live.Store(&restored)
		a.startGeneration(&restored)
	}
	return nil
}

// ReloadFile 读取、解析并应用配置文件（path 与启动时相同）。
// levelOverride 是启动参数 -log-level 的显式覆盖，非空时同样优先于文件值。
// 解析失败与构建失败一样保持旧配置继续服务，
// 并且每次尝试（无论失败在哪一步）都恰好计入一次 config_reloads_total。
func (a *App) ReloadFile(path, levelOverride string) error {
	cfg, err := config.Load(path, KnownProtocols)
	if err != nil {
		a.b.metrics.ConfigReload(metrics.ReloadError)
		return err
	}
	if levelOverride != "" {
		cfg.Log.Level = levelOverride
	}
	return a.Reload(cfg)
}
