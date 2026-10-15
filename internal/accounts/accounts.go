// Package accounts 是账户聚合的 L2 领域包：动态用户/订阅存储 + 版本化
// JSON 文件持久化 + 门禁读视图（GateView）。
//
// 职责边界（设计书 §2.1）：
//   - HTTP-free / gin-free / core-free：数据面契约（core.Authenticator、
//     trojan.Verifier）由 GateView 以方法形状结构化满足，本包不感知消费方；
//   - 凭据纪律（镜像 internal/auth）：文件与内存只保存 sha256（入站比对）/
//     sha224（隧道反查）十六进制摘要，明文永不落盘；同隧道摘要（同口令）
//     的用户互斥；
//   - 启动期 fail-closed：文件缺失/损坏/格式漂移一律拒绝启动；空账户列表
//     合法（空库 + 门禁开启 = 全员拒绝，本就是 fail-closed 语义）。
//
// 单写者前提：持久化不做跨进程文件锁，同一文件只允许一个进程写（部署保证）。
package accounts

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// UserStatus 是账户状态：active（可用）| disabled（停用）。
// 只停用不删除（后续订单以用户名字符串引用账户，物理删除会制造孤儿引用）。
type UserStatus string

const (
	StatusActive   UserStatus = "active"
	StatusDisabled UserStatus = "disabled"
)

// Subscription 是账户的订阅；零值 = 无订阅。
type Subscription struct {
	// ExpiresAt 是订阅到期时刻（不含）：now < ExpiresAt 视为有效。
	ExpiresAt time.Time
	// GrantedAt 是订阅授予（购买/管理员设置）时刻：now < GrantedAt 说明
	// 系统时钟早于授予时刻（时钟回拨），按拒绝处理（fail-closed）。
	GrantedAt time.Time
}

// User 是一个账户的导出形态（聚合根快照）：凭据只携带摘要、不携带明文，
// 摘要为小写十六进制（Store 归一化后返回）。
type User struct {
	Username string
	// PasswordSHA256 是口令的 SHA-256 摘要（入站认证比对用）。
	PasswordSHA256 string
	// PasswordSHA224 是口令的 SHA-224 摘要（隧道反查用）。
	PasswordSHA224 string
	Status         UserStatus
	Subscription   Subscription
}

// 错误集（调用方以 errors.Is 区分；文件与持久化错误以包装错误返回）。
var (
	// ErrDuplicateUsername 用户名重复（身份命名空间唯一）。
	ErrDuplicateUsername = errors.New("accounts: duplicate username")
	// ErrTunnelHashConflict 与既有用户的口令 SHA-224 摘要相同（隧道侧无法
	// 区分同口令用户——镜像 auth.Store 的不变量）。
	ErrTunnelHashConflict = errors.New("accounts: users must not share the same password")
	// ErrUnknownUser 用户名不存在。
	ErrUnknownUser = errors.New("accounts: unknown user")
	// ErrInvalidUser 字段形状非法（用户名 / 摘要 / 状态 / 订阅）。
	ErrInvalidUser = errors.New("accounts: invalid user")
	// ErrReadOnly 只读存储（LoadReadOnly 产物）不接受变更。
	ErrReadOnly = errors.New("accounts: store is read-only")
)

// userRecord 是 Store 内部的账户行：凭据以原始摘要字节持有（校验一次、
// 比较零解码开销），导出为 User 时转十六进制。
type userRecord struct {
	username  string
	sha256Sum [sha256.Size]byte
	sha224Sum [sha256.Size224]byte
	status    UserStatus
	sub       Subscription
}

// user 导出为 User（摘要转小写十六进制）。
func (r userRecord) user() User {
	return User{
		Username:       r.username,
		PasswordSHA256: hex.EncodeToString(r.sha256Sum[:]),
		PasswordSHA224: hex.EncodeToString(r.sha224Sum[:]),
		Status:         r.status,
		Subscription:   r.sub,
	}
}

// Store 是动态账户存储：RWMutex 保护的内存态 +（可选）文件持久化。
//
// 变更类操作（Create / SetStatus / SetSubscriptionExpiresAt）先原子落盘、
// 成功后再应用内存（文件是权威状态，进程崩溃不会留下内存与文件不一致的
// 中间态）。Open 构建的 Store 可变（变更即落盘）；LoadReadOnly 构建的
// Store 只读（变更返回 ErrReadOnly）。构造后可安全并发使用。
type Store struct {
	// Now 是时钟注入点：订阅有效性判定与授予时刻用它取当前时刻。
	// 具体类型字段（非接口）；构造时缺省 time.Now，测试注入假时钟。
	Now func() time.Time

	mu     sync.RWMutex
	names  []string                        // 用户名插入序（文件与 List 输出稳定）
	users  map[string]userRecord           // 用户名 → 账户行
	tunnel map[[sha256.Size224]byte]string // sha224 摘要 → 用户名
	path   string                          // 非空 = 可变并持久化到该文件
}

// Create 新建账户。u.Status 为空时按 active 处理；摘要必须是正确长度的
// 十六进制串（内部统一规范为小写）；订阅形状必须完整（见 validateSubscription）。
// 重复用户名与同隧道摘要（同口令）冲突会被拒绝。
func (s *Store) Create(u User) error {
	rec, err := newRecord(u)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.users[rec.username]; dup {
		return fmt.Errorf("%w: %q", ErrDuplicateUsername, rec.username)
	}
	if existing, conflict := s.tunnel[rec.sha224Sum]; conflict {
		return fmt.Errorf("%w: users %q and %q must not share the same password", ErrTunnelHashConflict, existing, rec.username)
	}
	next := s.snapshotLocked()
	next = append(next, rec)
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.names = append(s.names, rec.username)
	s.users[rec.username] = rec
	s.tunnel[rec.sha224Sum] = rec.username
	return nil
}

// SetStatus 设置账户状态（active | disabled；只停用不删除）。幂等：状态
// 未变化时不落盘。
func (s *Store) SetStatus(username string, status UserStatus) error {
	if status != StatusActive && status != StatusDisabled {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidUser, status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.users[username]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownUser, username)
	}
	if rec.status == status {
		return nil
	}
	rec.status = status
	next := s.snapshotLocked()
	for i := range next {
		if next[i].username == username {
			next[i].status = status
		}
	}
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.users[username] = rec
	return nil
}

// SetSubscriptionExpiresAt 管理员设置订阅到期时刻（人工纠错通道，可任意
// 设置，含过去时刻 = 即刻过期语义）；授予时刻取当前时钟（时钟回拨检测的
// 基准随本次授予更新）。expiresAt 零值 = 清除订阅（回到无订阅）。
func (s *Store) SetSubscriptionExpiresAt(username string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.users[username]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownUser, username)
	}
	sub := Subscription{ExpiresAt: expiresAt}
	if !expiresAt.IsZero() {
		sub.GrantedAt = s.now()
	}
	rec.sub = sub
	next := s.snapshotLocked()
	for i := range next {
		if next[i].username == username {
			next[i].sub = sub
		}
	}
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.users[username] = rec
	return nil
}

// Get 返回账户快照（副本；修改返回值不影响存储）。
func (s *Store) Get(username string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.users[username]
	if !ok {
		return User{}, fmt.Errorf("%w: %q", ErrUnknownUser, username)
	}
	return rec.user(), nil
}

// List 返回全部账户快照（插入序）。
func (s *Store) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.names))
	for _, name := range s.names {
		out = append(out, s.users[name].user())
	}
	return out
}

// Len 返回账户数。
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.names)
}

// —— 门禁读路径（GateView 消费；方法不对导出面承诺，形状见 gate.go）——

// lookup 返回账户行与存在性（快照语义：调用方拿到的副本不再随存储变化）。
func (s *Store) lookup(username string) (userRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.users[username]
	return rec, ok
}

// lookupTunnel 遍历隧道摘要索引做常量时间比较（不因命中提前返回——镜像
// auth.Store 的时序纪律），返回匹配的账户行。
func (s *Store) lookupTunnel(hashHex string) (userRecord, bool) {
	hashHex = strings.TrimSpace(hashHex)
	if len(hashHex) != sha256.Size224*2 {
		return userRecord{}, false
	}
	raw, err := hex.DecodeString(hashHex)
	if err != nil || len(raw) != sha256.Size224 {
		return userRecord{}, false
	}
	var key [sha256.Size224]byte
	copy(key[:], raw)
	s.mu.RLock()
	defer s.mu.RUnlock()
	var matched userRecord
	found := false
	for sum, name := range s.tunnel {
		if subtle.ConstantTimeCompare(key[:], sum[:]) == 1 {
			matched, found = s.users[name], true
		}
	}
	return matched, found
}

// now 返回当前时刻（Now 注入点；nil 回退 time.Now）。
func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// —— 变更辅助（调用方持写锁）——

// snapshotLocked 返回当前账户行列表（插入序）。
func (s *Store) snapshotLocked() []userRecord {
	out := make([]userRecord, 0, len(s.names))
	for _, name := range s.names {
		out = append(out, s.users[name])
	}
	return out
}

// saveLocked 把变更后的完整账户列表原子落盘。只读 Store（path 为空）在
// 此拒绝一切变更；落盘成功后由调用方应用内存变更（文件先行）。
func (s *Store) saveLocked(next []userRecord) error {
	if s.path == "" {
		return ErrReadOnly
	}
	if err := saveFile(s.path, next); err != nil {
		return fmt.Errorf("accounts: persist %s: %w", s.path, err)
	}
	return nil
}

// —— 校验与归一化（文件加载与 Create 共用同一条路径）——

// newRecord 校验并归一化导出 User 为内部行（凭据纪律：只接受摘要形态）。
func newRecord(u User) (userRecord, error) {
	if strings.TrimSpace(u.Username) == "" {
		return userRecord{}, fmt.Errorf("%w: username must not be empty", ErrInvalidUser)
	}
	if strings.ContainsAny(u.Username, "\r\n") {
		return userRecord{}, fmt.Errorf("%w: username %q must not contain CR or LF", ErrInvalidUser, u.Username)
	}
	sum256, err := decodeDigest(u.PasswordSHA256, sha256.Size, "password_sha256")
	if err != nil {
		return userRecord{}, err
	}
	sum224, err := decodeDigest(u.PasswordSHA224, sha256.Size224, "password_sha224")
	if err != nil {
		return userRecord{}, err
	}
	status := u.Status
	if status == "" {
		status = StatusActive // 缺省启用（创建语义；文件格式同源）
	}
	if status != StatusActive && status != StatusDisabled {
		return userRecord{}, fmt.Errorf("%w: unknown status %q", ErrInvalidUser, status)
	}
	if err := validateSubscription(u.Subscription); err != nil {
		return userRecord{}, err
	}
	rec := userRecord{username: u.Username, status: status, sub: u.Subscription}
	copy(rec.sha256Sum[:], sum256)
	copy(rec.sha224Sum[:], sum224)
	return rec, nil
}

// decodeDigest 校验十六进制摘要形状并返回原始字节；存储统一保存小写规范形
// （hex 解码 + 重编码承担大小写归一）。
func decodeDigest(hexStr string, size int, what string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexStr))
	if err != nil || len(raw) != size {
		return nil, fmt.Errorf("%w: %s must be a %d-character hex digest (got %q)", ErrInvalidUser, what, size*2, hexStr)
	}
	return raw, nil
}

// validateSubscription 校验订阅形状：无订阅（零值）或完整订阅（到期与授予
// 时刻都非零）二选一，不允许半填写（半写的订阅无法参与时钟回拨判定）。
func validateSubscription(sub Subscription) error {
	if sub.ExpiresAt.IsZero() && sub.GrantedAt.IsZero() {
		return nil
	}
	if sub.ExpiresAt.IsZero() || sub.GrantedAt.IsZero() {
		return fmt.Errorf("%w: subscription must set both expires_at and granted_at (or neither)", ErrInvalidUser)
	}
	return nil
}
