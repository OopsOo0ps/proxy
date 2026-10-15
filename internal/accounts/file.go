package accounts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// 账户文件格式（版本化 JSON，单写者；客户端只读模式复用同一格式）：
//
//	{
//	  "version": 1,
//	  "users": [
//	    {
//	      "username": "alice",
//	      "password_sha256": "<64 位十六进制，入站比对摘要>",
//	      "password_sha224": "<56 位十六进制，隧道反查摘要>",
//	      "status": "active",
//	      "subscription": { "expires_at": "RFC3339", "granted_at": "RFC3339" }
//	    }
//	  ]
//	}
//
// 严格加载：未知字段 / 未知版本 / 尾随数据 / 非法摘要或状态 / 重复用户名 /
// 同隧道摘要冲突一律报错（启动期 fail-closed，设计书 §3.3）；status 缺省按
// active 处理；空 users 列表合法（空库）。
// 原子持久化：写同目录临时文件 + fsync + rename。任意时刻进程退出，要么旧
// 文件完好（rename 前），要么新文件完整（rename 后）；遗留的临时文件不被
// 加载路径读取，下次落盘即清理。
const fileVersion = 1

// fileFormat 是账户文件的信封。
type fileFormat struct {
	Version int        `json:"version"`
	Users   []fileUser `json:"users"`
}

// fileUser 是账户文件的行记录（导出模型 User 的持久化形态：时间以 RFC3339
// 字符串表达，无订阅时 subscription 整体省略）。
type fileUser struct {
	Username       string     `json:"username"`
	PasswordSHA256 string     `json:"password_sha256"`
	PasswordSHA224 string     `json:"password_sha224"`
	Status         UserStatus `json:"status"`
	Subscription   *fileSub   `json:"subscription,omitempty"`
}

// fileSub 是订阅的持久化形态（零值时刻省略；到期与授予时刻成对出现）。
type fileSub struct {
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	GrantedAt *time.Time `json:"granted_at,omitempty"`
}

// Open 严格加载账户文件并返回可变 Store（变更即原子落盘）。文件缺失/损坏/
// 格式漂移一律报错——启动期 fail-closed（设计书 §3.3）；空账户列表合法。
func Open(path string) (*Store, error) {
	records, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	return newStore(path, records), nil
}

// LoadReadOnly 以同一文件格式严格加载只读 Store（客户端 entitlement 场景：
// 只读消费，变更返回 ErrReadOnly）。缺失/损坏同样报错（启动期从未成功加载
// ⇒ 拒绝启动；运行期重载失败沿沿用旧配置的语义属上层热加载职责）。
func LoadReadOnly(path string) (*Store, error) {
	records, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	return newStore("", records), nil
}

// newStore 以已校验的账户行构建 Store（path 为空 = 只读）。
func newStore(path string, records []userRecord) *Store {
	s := &Store{
		Now:    time.Now,
		users:  make(map[string]userRecord, len(records)),
		tunnel: make(map[[sha256.Size224]byte]string, len(records)),
		path:   path,
	}
	for _, rec := range records {
		s.names = append(s.names, rec.username)
		s.users[rec.username] = rec
		s.tunnel[rec.sha224Sum] = rec.username
	}
	return s
}

// loadFile 严格加载账户文件并返回内部账户行（保持文件顺序）。
func loadFile(path string) ([]userRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("accounts: load %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f fileFormat
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("accounts: load %s: %w", path, err)
	}
	// 严格性补充：文件必须是恰好一个 JSON 值，拒绝尾随数据。
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("accounts: load %s: unexpected trailing data", path)
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("accounts: load %s: unsupported version %d (want %d)", path, f.Version, fileVersion)
	}

	records := make([]userRecord, 0, len(f.Users))
	seen := make(map[string]bool, len(f.Users))
	tunnel := make(map[[sha256.Size224]byte]string, len(f.Users))
	for i, fu := range f.Users {
		rec, err := newRecord(fu.user())
		if err != nil {
			return nil, fmt.Errorf("accounts: load %s: users[%d]: %w", path, i, err)
		}
		if seen[rec.username] {
			return nil, fmt.Errorf("accounts: load %s: users[%d]: %w: %q", path, i, ErrDuplicateUsername, rec.username)
		}
		if existing, conflict := tunnel[rec.sha224Sum]; conflict {
			return nil, fmt.Errorf("accounts: load %s: users[%d]: %w: users %q and %q must not share the same password", path, i, ErrTunnelHashConflict, existing, rec.username)
		}
		seen[rec.username] = true
		tunnel[rec.sha224Sum] = rec.username
		records = append(records, rec)
	}
	return records, nil
}

// saveFile 把账户行原子写入 path：序列化 → 同目录临时文件 → fsync →
// rename（同目录保证同一文件系统内原子替换）。
func saveFile(path string, records []userRecord) error {
	f := fileFormat{Version: fileVersion, Users: make([]fileUser, 0, len(records))}
	for _, rec := range records {
		f.Users = append(f.Users, fileUserOf(rec))
	}
	data, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	data = append(data, '\n')

	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // rename 成功后无此文件；失败路径清理半写临时文件

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	// rename 落盘后同步目录项：保证掉电后 rename 本身不丢（文件内容已 fsync）。
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

// user 转换为导出模型（文件形态 → 领域形态）。
func (f fileUser) user() User {
	u := User{
		Username:       f.Username,
		PasswordSHA256: f.PasswordSHA256,
		PasswordSHA224: f.PasswordSHA224,
		Status:         f.Status,
	}
	if f.Subscription != nil {
		if f.Subscription.ExpiresAt != nil {
			u.Subscription.ExpiresAt = *f.Subscription.ExpiresAt
		}
		if f.Subscription.GrantedAt != nil {
			u.Subscription.GrantedAt = *f.Subscription.GrantedAt
		}
	}
	return u
}

// fileUserOf 转换为持久化形态（领域形态 → 文件形态；无订阅整体省略）。
func fileUserOf(rec userRecord) fileUser {
	fu := fileUser{
		Username:       rec.username,
		PasswordSHA256: hex.EncodeToString(rec.sha256Sum[:]),
		PasswordSHA224: hex.EncodeToString(rec.sha224Sum[:]),
		Status:         rec.status,
	}
	if !rec.sub.ExpiresAt.IsZero() || !rec.sub.GrantedAt.IsZero() {
		fu.Subscription = &fileSub{
			ExpiresAt: timePtr(rec.sub.ExpiresAt),
			GrantedAt: timePtr(rec.sub.GrantedAt),
		}
	}
	return fu
}

// timePtr 把零值时刻折叠为 JSON 缺省（null → 字段省略）。
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
