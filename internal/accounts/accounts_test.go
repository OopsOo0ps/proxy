package accounts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// —— 假时钟与夹具（设计书 §5：假时钟 + TempDir 真 Store，持久化轻到不值得 mock）——

// fakeClock 是可步进的假时钟（-race 下经互斥锁读写）。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

const testPassword = "change-me-alice"

func sha256HexOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha224HexOf(s string) string {
	sum := sha256.Sum224([]byte(s))
	return hex.EncodeToString(sum[:])
}

func testUser(name, password string) User {
	return User{
		Username:       name,
		PasswordSHA256: sha256HexOf(password),
		PasswordSHA224: sha224HexOf(password),
		Status:         StatusActive,
	}
}

// userLine 生成 users 数组的一个元素（无订阅的最小形状）。
func userLine(username, sha256Hex, sha224Hex, status string) string {
	return `{"username": "` + username + `", "password_sha256": "` + sha256Hex + `", "password_sha224": "` + sha224Hex + `", "status": "` + status + `"}`
}

// fileWith 组装账户文件内容。
func fileWith(version string, users ...string) string {
	return `{"version": ` + version + `, "users": [` + strings.Join(users, ",\n") + `]}`
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustOpen(t *testing.T, path string) *Store {
	t.Helper()
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return st
}

func mustFailOpen(t *testing.T, content, want string) {
	t.Helper()
	path := writeFile(t, content)
	if _, err := Open(path); err == nil {
		t.Fatalf("Open must fail, want error containing %q", want)
	} else if !strings.Contains(err.Error(), want) {
		t.Fatalf("Open error = %q, want containing %q", err.Error(), want)
	}
}

// —— 严格加载负例（启动期 fail-closed，D §3.3）——

func TestOpenMissingFileFails(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("Open of a missing file must fail (fail-closed startup)")
	}
}

func TestOpenRejectsCorruptFile(t *testing.T) {
	mustFailOpen(t, "not json at all", "accounts: load")
	mustFailOpen(t, `{"version": 1, "users": [`, "accounts: load")
	mustFailOpen(t, fileWith("1")+`{"version": 1, "users": []}`, "unexpected trailing data")
}

func TestOpenRejectsUnknownField(t *testing.T) {
	mustFailOpen(t, `{"version": 1, "users": [], "extra": 1}`, "unknown field")
	mustFailOpen(t, `{"version": 1, "users": [{"username": "a", "password_sha256": "`+strings.Repeat("a", 64)+`", "password_sha224": "`+strings.Repeat("b", 56)+`", "status": "active", "bogus": 1}]}`, "unknown field")
}

func TestOpenRejectsUnknownVersion(t *testing.T) {
	mustFailOpen(t, fileWith("2"), "unsupported version 2")
	// 版本字段缺失 = 未知版本（0），同样拒绝。
	mustFailOpen(t, `{"users": []}`, "unsupported version 0")
}

func TestOpenRejectsBadDigest(t *testing.T) {
	mustFailOpen(t, fileWith("1", userLine("alice", "abc", sha224HexOf("pw"), "active")),
		"password_sha256 must be a 64-character hex digest")
	mustFailOpen(t, fileWith("1", userLine("alice", sha256HexOf("pw"), "xyz", "active")),
		"password_sha224 must be a 56-character hex digest")
}

func TestOpenRejectsUnknownStatus(t *testing.T) {
	mustFailOpen(t, fileWith("1", userLine("alice", sha256HexOf("pw"), sha224HexOf("pw"), "banned")),
		`unknown status "banned"`)
}

func TestOpenRejectsIncompleteSubscription(t *testing.T) {
	// 订阅半填写（只有到期、无授予时刻）无法参与时钟回拨判定，加载即拒绝。
	content := `{"version": 1, "users": [{"username": "alice", "password_sha256": "` + sha256HexOf("pw") +
		`", "password_sha224": "` + sha224HexOf("pw") + `", "status": "active", ` +
		`"subscription": {"expires_at": "2027-01-01T00:00:00Z"}}]}`
	mustFailOpen(t, content, "must set both expires_at and granted_at")
}

func TestOpenRejectsDuplicateUsername(t *testing.T) {
	mustFailOpen(t, fileWith("1",
		userLine("alice", sha256HexOf("pw-a"), sha224HexOf("pw-a"), "active"),
		userLine("alice", sha256HexOf("pw-b"), sha224HexOf("pw-b"), "active"),
	), "duplicate username")
}

func TestOpenRejectsTunnelConflict(t *testing.T) {
	// 同口令的两个用户（sha224 相同）：隧道侧无法区分，镜像 auth.Store 不变量。
	mustFailOpen(t, fileWith("1",
		userLine("alice", sha256HexOf("pw-a"), sha224HexOf("same-pw"), "active"),
		userLine("bob", sha256HexOf("pw-b"), sha224HexOf("same-pw"), "active"),
	), "must not share the same password")
}

func TestOpenEmptyListLegal(t *testing.T) {
	// 空账户列表合法启动（D §3.3）：空库 + 门禁开启 = 全员拒绝，本就是 fail-closed。
	path := writeFile(t, fileWith("1"))
	st := mustOpen(t, path)
	if st.Len() != 0 || len(st.List()) != 0 {
		t.Fatalf("empty library = %d users", st.Len())
	}
	g := NewGateView(st)
	if g.Authenticate("alice", testPassword) {
		t.Fatal("empty library must reject any credential")
	}

	ro, err := LoadReadOnly(path)
	if err != nil {
		t.Fatalf("LoadReadOnly: %v", err)
	}
	if ro.Len() != 0 {
		t.Fatalf("empty library = %d users", ro.Len())
	}

	if err := st.Create(testUser("alice", testPassword)); err != nil {
		t.Fatalf("Create on empty library: %v", err)
	}
}

// —— CRUD 与凭据纪律 ——

func TestCreateValidatesAndNormalizes(t *testing.T) {
	st := mustOpen(t, writeFile(t, fileWith("1")))

	// 大写十六进制输入归一为小写规范形。
	u := testUser("alice", testPassword)
	u.PasswordSHA256 = strings.ToUpper(u.PasswordSHA256)
	u.PasswordSHA224 = strings.ToUpper(u.PasswordSHA224)
	if err := st.Create(u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := st.Get("alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PasswordSHA256 != sha256HexOf(testPassword) || got.PasswordSHA224 != sha224HexOf(testPassword) {
		t.Fatalf("digests not normalized to lowercase: %+v", got)
	}
	if got.Status != StatusActive {
		t.Fatalf("status = %q, want active", got.Status)
	}

	// 重复用户名拒绝。
	if err := st.Create(testUser("alice", "other")); !errors.Is(err, ErrDuplicateUsername) {
		t.Fatalf("duplicate username err = %v, want ErrDuplicateUsername", err)
	}

	// 同隧道摘要（同口令）冲突拒绝——即使 sha256 不同（夹具构造的摘要形态）。
	conflict := User{Username: "bob", PasswordSHA256: sha256HexOf("pw-bob"), PasswordSHA224: sha224HexOf(testPassword)}
	if err := st.Create(conflict); !errors.Is(err, ErrTunnelHashConflict) {
		t.Fatalf("tunnel conflict err = %v, want ErrTunnelHashConflict", err)
	}

	// 形状负例。
	for _, bad := range []User{
		{Username: "  ", PasswordSHA256: sha256HexOf("p"), PasswordSHA224: sha224HexOf("p")},
		{Username: "a\r\nb", PasswordSHA256: sha256HexOf("p"), PasswordSHA224: sha224HexOf("p")},
		{Username: "ok", PasswordSHA256: "abc", PasswordSHA224: sha224HexOf("p")},
		{Username: "ok", PasswordSHA256: sha256HexOf("p"), PasswordSHA224: "zz"},
		{Username: "ok", PasswordSHA256: sha256HexOf("p"), PasswordSHA224: sha224HexOf("p"), Status: "banned"},
		{Username: "ok", PasswordSHA256: sha256HexOf("p"), PasswordSHA224: sha224HexOf("p"), Status: StatusActive,
			Subscription: Subscription{ExpiresAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}},
	} {
		if err := st.Create(bad); !errors.Is(err, ErrInvalidUser) {
			t.Fatalf("Create(%+v) err = %v, want ErrInvalidUser", bad, err)
		}
	}

	if st.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (all invalid creates rejected)", st.Len())
	}
}

func TestSetStatusPersists(t *testing.T) {
	path := writeFile(t, fileWith("1", userLine("alice", sha256HexOf("pw"), sha224HexOf("pw"), "active")))
	st := mustOpen(t, path)

	if err := st.SetStatus("alice", StatusDisabled); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if got, err := st.Get("alice"); err != nil || got.Status != StatusDisabled {
		t.Fatalf("Get after disable = %+v, %v", got, err)
	}
	// 幂等：重复停用不报错。
	if err := st.SetStatus("alice", StatusDisabled); err != nil {
		t.Fatalf("idempotent SetStatus: %v", err)
	}
	// 持久化生效：重新打开仍是停用。
	round := mustOpen(t, path)
	if u, err := round.Get("alice"); err != nil || u.Status != StatusDisabled {
		t.Fatalf("Get after reopen = %+v, %v; want persisted disabled status", u, err)
	}
	if err := st.SetStatus("alice", StatusActive); err != nil {
		t.Fatalf("re-enable: %v", err)
	}

	if err := st.SetStatus("ghost", StatusDisabled); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("unknown user err = %v, want ErrUnknownUser", err)
	}
	if err := st.SetStatus("alice", "banned"); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("invalid status err = %v, want ErrInvalidUser", err)
	}
	if _, err := st.Get("ghost"); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("Get unknown err = %v, want ErrUnknownUser", err)
	}
}

func TestSetSubscriptionExpiresAtUsesInjectedClock(t *testing.T) {
	path := writeFile(t, fileWith("1", userLine("alice", sha256HexOf("pw"), sha224HexOf("pw"), "active")))
	st := mustOpen(t, path)
	clock := newFakeClock(time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC))
	st.Now = clock.Now

	expires := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	if err := st.SetSubscriptionExpiresAt("alice", expires); err != nil {
		t.Fatalf("SetSubscriptionExpiresAt: %v", err)
	}
	got, err := st.Get("alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Subscription.ExpiresAt.Equal(expires) {
		t.Fatalf("expires_at = %v, want %v", got.Subscription.ExpiresAt, expires)
	}
	if !got.Subscription.GrantedAt.Equal(clock.Now()) {
		t.Fatalf("granted_at = %v, want injected now %v", got.Subscription.GrantedAt, clock.Now())
	}
	// RFC3339 往返：重新打开后订阅形状一致。
	round := mustOpen(t, path)
	got2, err := round.Get("alice")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if !got2.Subscription.ExpiresAt.Equal(expires) || !got2.Subscription.GrantedAt.Equal(clock.Now()) {
		t.Fatalf("subscription did not round-trip: %+v", got2.Subscription)
	}

	// 零值 = 清除订阅。
	if err := st.SetSubscriptionExpiresAt("alice", time.Time{}); err != nil {
		t.Fatalf("clear subscription: %v", err)
	}
	got3, _ := st.Get("alice")
	if !got3.Subscription.ExpiresAt.IsZero() || !got3.Subscription.GrantedAt.IsZero() {
		t.Fatalf("subscription not cleared: %+v", got3.Subscription)
	}
	if err := st.SetSubscriptionExpiresAt("ghost", expires); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("unknown user err = %v, want ErrUnknownUser", err)
	}
}

func TestLoadReadOnlyRejectsMutation(t *testing.T) {
	path := writeFile(t, fileWith("1", userLine("alice", sha256HexOf("pw"), sha224HexOf("pw"), "active")))
	ro, err := LoadReadOnly(path)
	if err != nil {
		t.Fatalf("LoadReadOnly: %v", err)
	}
	if ro.Len() != 1 {
		t.Fatalf("Len = %d, want 1", ro.Len())
	}
	if err := ro.Create(testUser("bob", "pw-b")); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Create err = %v, want ErrReadOnly", err)
	}
	if err := ro.SetStatus("alice", StatusDisabled); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("SetStatus err = %v, want ErrReadOnly", err)
	}
	if err := ro.SetSubscriptionExpiresAt("alice", time.Now()); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("SetSubscriptionExpiresAt err = %v, want ErrReadOnly", err)
	}
	// 只读存储读路径正常。
	if u, err := ro.Get("alice"); err != nil || u.Username != "alice" {
		t.Fatalf("Get on read-only store = %+v, %v", u, err)
	}
}

// —— 原子持久化（tmp + rename；中断可恢复）——

func TestAtomicPersistRecoversFromInterruption(t *testing.T) {
	path := writeFile(t, fileWith("1", userLine("alice", sha256HexOf("pw-a"), sha224HexOf("pw-a"), "active")))

	// 模拟一次中断的原子写：遗留半写的临时文件，主文件完好（rename 前中断）。
	staleTmp := path + ".tmp-stale"
	if err := os.WriteFile(staleTmp, []byte(`{"version": 1, "users": [{"username": "ghost"`), 0o600); err != nil {
		t.Fatal(err)
	}

	st := mustOpen(t, path)
	if st.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (old file intact, stale temp ignored)", st.Len())
	}
	if users := st.List(); users[0].Username != "alice" {
		t.Fatalf("users[0] = %+v, want alice", users[0])
	}

	// 遗留临时文件不影响后续落盘；rename 原子替换主文件。
	if err := st.Create(testUser("bob", "pw-b")); err != nil {
		t.Fatalf("Create after interruption: %v", err)
	}
	round := mustOpen(t, path)
	if round.Len() != 2 {
		t.Fatalf("Len after reopen = %d, want 2", round.Len())
	}
	names := []string{}
	for _, u := range round.List() {
		names = append(names, u.Username)
	}
	if strings.Join(names, ",") != "alice,bob" {
		t.Fatalf("user order = %v, want [alice bob] (file order stable)", names)
	}

	// 落盘内容是规范形状：版本 1 + 小写十六进制摘要。
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"version": 1`) || !strings.Contains(string(data), sha224HexOf("pw-b")) {
		t.Fatalf("persisted file malformed:\n%s", data)
	}
}

// —— 并发（-race 下 CRUD 与门禁读路径）——

func TestConcurrentCRUDAndGate(t *testing.T) {
	path := writeFile(t, fileWith("1"))
	st := mustOpen(t, path)
	clock := newFakeClock(time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	st.Now = clock.Now // 注入发生在并发之前（happens-before goroutine 启动）

	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		name, pw := fmt.Sprintf("user-%d", i), fmt.Sprintf("pw-%d", i)
		wg.Add(3)
		go func() {
			defer wg.Done()
			if err := st.Create(testUser(name, pw)); err != nil {
				t.Errorf("Create(%s): %v", name, err)
			}
		}()
		go func() {
			defer wg.Done()
			_ = st.List()
			_, _ = st.Get(name) // 未创建完成时允许失败，仅验证并发读不 panic
		}()
		go func() {
			defer wg.Done()
			g := NewGateView(st)
			_ = g.Authenticate(name, pw)
			_, _ = g.VerifyTunnel(sha224HexOf(pw))
		}()
	}
	wg.Wait()

	if st.Len() != n {
		t.Fatalf("Len = %d, want %d", st.Len(), n)
	}
	// 每次变更都落盘：重新打开后全部账户仍在。
	if round := mustOpen(t, path); round.Len() != n {
		t.Fatalf("Len after reopen = %d, want %d", round.Len(), n)
	}
}
