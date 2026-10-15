package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/accounts"
)

// —— 测试脚手架：httptest + t.TempDir() 的真实账户存储（不 mock 领域层，
// 设计书 §5）——

// newTestServer 起一个 httptest 控制面与真实 accounts Store：账户文件先落盘
// （严格加载要求文件存在），变更经控制面写入后可从磁盘重新加载验证。返回
// Store、账户文件路径（落盘验证用）与 httptest 服务。
func newTestServer(t *testing.T) (*accounts.Store, string, *httptest.Server) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.json")
	if err := os.WriteFile(path, []byte("{\"version\":1,\"users\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := accounts.Open(path)
	if err != nil {
		t.Fatalf("accounts.Open: %v", err)
	}
	srv, err := New(Deps{Store: store, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}
	ts := httptest.NewServer(srv.handler)
	t.Cleanup(ts.Close)
	return store, path, ts
}

// doJSON 发送 JSON 请求并返回状态码与解码后的响应体。
func doJSON(t *testing.T, ts *httptest.Server, method, target string, body any) (int, map[string]any) {
	t.Helper()
	code, raw := doRaw(t, ts, method, target, body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: decode response %q: %v", method, target, raw, err)
		}
	}
	return code, out
}

// doRaw 发送 JSON 请求并返回状态码与原始响应体（断言不回显凭据时用）。
func doRaw(t *testing.T, ts *httptest.Server, method, target string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, ts.URL+target, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read response: %v", method, target, err)
	}
	return resp.StatusCode, raw
}

// reopenStore 从磁盘重新加载账户文件（验证控制面变更确实落盘）。
func reopenStore(t *testing.T, path string) *accounts.Store {
	t.Helper()
	reopened, err := accounts.Open(path)
	if err != nil {
		t.Fatalf("reopen accounts file: %v", err)
	}
	return reopened
}

// —— CRUD 正常路径 ——
//
// 创建 → 列表 → 停用/启用（GateView 判定翻转）→ 设置 expires_at → 清除订阅，
// 全程断言：凭据明文与摘要不出现在任何响应里，且变更确实落盘。
func TestUsersCRUDHappyPath(t *testing.T) {
	store, path, ts := newTestServer(t)
	gate := accounts.NewGateView(store)

	const (
		username = "alice"
		password = "pw-alice-2026"
	)
	hash224 := hex.EncodeToString(func() []byte { s := sha256.Sum224([]byte(password)); return s[:] }())

	// 创建：201，返回视图不含订阅。
	code, body := doJSON(t, ts, http.MethodPost, "/users", map[string]string{"username": username, "password": password})
	if code != http.StatusCreated {
		t.Fatalf("create: got status %d, want 201 (body: %v)", code, body)
	}
	if body["username"] != username || body["status"] != string(accounts.StatusActive) {
		t.Fatalf("create: unexpected view %v", body)
	}
	if _, has := body["password_sha256"]; has {
		t.Fatal("create: response must not echo credential digests")
	}

	// 变更已落盘：磁盘重读可见该用户。
	if disk := reopenStore(t, path); disk.Len() != 1 {
		t.Fatalf("after create: disk store has %d users, want 1", disk.Len())
	}

	// 列表响应不携带凭据明文与隧道摘要（凭据纪律：摘要不出控制面）。
	code, raw := doRaw(t, ts, http.MethodGet, "/users", nil)
	if code != http.StatusOK {
		t.Fatalf("list: got status %d, want 200", code)
	}
	for _, secret := range []string{password, hash224, "password_sha"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("list: response leaks credential material %q: %s", secret, raw)
		}
	}
	var list listResponse
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("list: decode: %v", err)
	}
	if len(list.Users) != 1 {
		t.Fatalf("list: got %d users, want 1", len(list.Users))
	}

	// 停用：GateView 判定翻转（门禁关闭时订阅维度不参与，状态维度生效）。
	code, body = doJSON(t, ts, http.MethodPatch, "/users/"+username, map[string]string{"status": string(accounts.StatusDisabled)})
	if code != http.StatusOK || body["status"] != string(accounts.StatusDisabled) {
		t.Fatalf("disable: got status %d body %v, want 200 disabled", code, body)
	}
	if gate.Authenticate(username, password) {
		t.Fatal("after disable: gate view must reject the correct password")
	}
	// 启用：恢复放行。
	code, body = doJSON(t, ts, http.MethodPatch, "/users/"+username, map[string]string{"status": string(accounts.StatusActive)})
	if code != http.StatusOK || body["status"] != string(accounts.StatusActive) {
		t.Fatalf("enable: got status %d body %v, want 200 active", code, body)
	}
	if !gate.Authenticate(username, password) {
		t.Fatal("after enable: gate view must accept the correct password")
	}

	// 设置订阅：expires_at 进入视图与磁盘。
	expires := time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339)
	code, body = doJSON(t, ts, http.MethodPut, "/users/"+username+"/subscription", map[string]string{"expires_at": expires})
	if code != http.StatusOK {
		t.Fatalf("set subscription: got status %d, want 200 (body: %v)", code, body)
	}
	sub, _ := body["subscription"].(map[string]any)
	if sub == nil || sub["expires_at"] == "" {
		t.Fatalf("set subscription: view must carry expires_at, got %v", body)
	}
	u, err := store.Get(username)
	if err != nil || u.Subscription.ExpiresAt.Format(time.RFC3339) != expires {
		t.Fatalf("set subscription: store expires_at = %v (err %v), want %s", u.Subscription.ExpiresAt, err, expires)
	}

	// 清除订阅（null = PUT 整置回无订阅）。
	code, body = doJSON(t, ts, http.MethodPut, "/users/"+username+"/subscription", map[string]any{"expires_at": nil})
	if code != http.StatusOK {
		t.Fatalf("clear subscription: got status %d, want 200", code)
	}
	if _, has := body["subscription"]; has {
		t.Fatalf("clear subscription: view must omit subscription, got %v", body)
	}
	u, err = store.Get(username)
	if err != nil || !u.Subscription.ExpiresAt.IsZero() {
		t.Fatalf("clear subscription: store expires_at = %v (err %v), want zero", u.Subscription.ExpiresAt, err)
	}
}

// —— 409：重复用户名 / 同口令（同隧道摘要）冲突 ——
func TestCreateUserConflicts(t *testing.T) {
	_, _, ts := newTestServer(t)

	if code, _ := doJSON(t, ts, http.MethodPost, "/users", map[string]string{"username": "alice", "password": "shared-pw"}); code != http.StatusCreated {
		t.Fatalf("create alice: got status %d, want 201", code)
	}
	// 重复用户名。
	code, body := doJSON(t, ts, http.MethodPost, "/users", map[string]string{"username": "alice", "password": "other-pw"})
	if code != http.StatusConflict {
		t.Fatalf("duplicate username: got status %d, want 409 (body: %v)", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "username") {
		t.Fatalf("duplicate username: error message %q should mention username", msg)
	}
	// 同口令（同隧道摘要）冲突：不同用户名、相同口令。
	code, body = doJSON(t, ts, http.MethodPost, "/users", map[string]string{"username": "bob", "password": "shared-pw"})
	if code != http.StatusConflict {
		t.Fatalf("same-password conflict: got status %d, want 409 (body: %v)", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "password") {
		t.Fatalf("same-password conflict: error message %q should mention password", msg)
	}
}

// —— 400：非法 body / 字段 ——
func TestCreateUserInvalidRequests(t *testing.T) {
	store, _, ts := newTestServer(t)

	// 损坏的 JSON。
	resp, err := http.Post(ts.URL+"/users", "application/json", strings.NewReader("{not-json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON: got status %d, want 400", resp.StatusCode)
	}

	// 字段形状负例：全部 400，且不产生半写状态。
	invalid := []map[string]string{
		{"username": "", "password": "pw"},
		{"username": "   ", "password": "pw"},
		{"username": "alice", "password": ""},
		{"username": "alice"},
		{"password": "pw"},
		{"username": "ali\nce", "password": "pw"},
		{"username": "alice", "password": "p\nw"},
	}
	for i, body := range invalid {
		code, resp := doJSON(t, ts, http.MethodPost, "/users", body)
		if code != http.StatusBadRequest {
			t.Fatalf("case %d (%v): got status %d, want 400", i, body, code)
		}
		if _, has := resp["error"]; !has {
			t.Fatalf("case %d: error response must carry an \"error\" field", i)
		}
	}
	if store.Len() != 0 {
		t.Fatalf("after invalid requests: store has %d users, want 0 (no partial writes)", store.Len())
	}
}

// —— 404 / 400：PATCH 未知用户与非法状态值 ——
func TestPatchUserErrors(t *testing.T) {
	store, _, ts := newTestServer(t)
	seedUser(t, ts, "alice", "pw-alice")

	// 未知用户 ⇒ 404。
	code, body := doJSON(t, ts, http.MethodPatch, "/users/ghost", map[string]string{"status": "disabled"})
	if code != http.StatusNotFound {
		t.Fatalf("unknown user: got status %d, want 404 (body: %v)", code, body)
	}
	// 非法状态值 ⇒ 400。
	code, _ = doJSON(t, ts, http.MethodPatch, "/users/alice", map[string]string{"status": "banned"})
	if code != http.StatusBadRequest {
		t.Fatalf("unknown status value: got status %d, want 400", code)
	}
	// 空 body（缺 status 字段）⇒ 400。
	code, _ = doJSON(t, ts, http.MethodPatch, "/users/alice", map[string]any{})
	if code != http.StatusBadRequest {
		t.Fatalf("missing status field: got status %d, want 400", code)
	}
	// 用户状态未受非法请求影响。
	u, err := store.Get("alice")
	if err != nil || u.Status != accounts.StatusActive {
		t.Fatalf("after invalid patches: status = %q (err %v), want active", u.Status, err)
	}
}

// —— 404 / 400：PUT subscription 未知用户与非法时刻 ——
func TestPutSubscriptionErrors(t *testing.T) {
	_, _, ts := newTestServer(t)
	seedUser(t, ts, "alice", "pw-alice")

	// 未知用户 ⇒ 404。
	code, body := doJSON(t, ts, http.MethodPut, "/users/ghost/subscription", map[string]string{"expires_at": "2027-01-01T00:00:00Z"})
	if code != http.StatusNotFound {
		t.Fatalf("unknown user: got status %d, want 404 (body: %v)", code, body)
	}
	// 非法时刻格式 ⇒ 400。
	code, _ = doJSON(t, ts, http.MethodPut, "/users/alice/subscription", map[string]string{"expires_at": "next-tuesday"})
	if code != http.StatusBadRequest {
		t.Fatalf("invalid expires_at: got status %d, want 400", code)
	}
}

// TestHostLifecycleSemantics 锁定宿主形态契约（与 status.Server 逐字对齐）：
// 空 addr = no-op；未绑定 Serve 立即返回 nil；已绑定但 ctx 已取消时 Serve 返回
// ctx.Err() 且不认领监听；Close 幂等、Addr 未绑定为空串。
func TestHostLifecycleSemantics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	if err := os.WriteFile(path, []byte("{\"version\":1,\"users\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := accounts.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Deps{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	// 未绑定：Addr 为空、Serve 立即返回 nil、Close 幂等。
	if got := srv.Addr(); got != "" {
		t.Fatalf("unbound Addr() = %q, want empty", got)
	}
	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("unbound Serve() = %v, want nil", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("unbound Close() = %v, want nil", err)
	}

	// 空 addr = no-op（不启用该端点）。
	if err := srv.Bind(""); err != nil {
		t.Fatalf("Bind(\"\") = %v, want nil", err)
	}
	if got := srv.Addr(); got != "" {
		t.Fatalf("after Bind(\"\"): Addr() = %q, want empty", got)
	}

	// 已绑定 + 已取消的 ctx：Serve 返回 ctx.Err()（不认领监听，status.Server 语义）。
	if err := srv.Bind("127.0.0.1:0"); err != nil {
		t.Fatalf("Bind(:0): %v", err)
	}
	if srv.Addr() == "" {
		t.Fatal("after Bind(:0): Addr() must be non-empty")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := srv.Serve(ctx); err == nil {
		t.Fatal("Serve with cancelled ctx must return ctx.Err()")
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close must stay nil (idempotent), got %v", err)
	}
	if got := srv.Addr(); got != "" {
		t.Fatalf("after Close: Addr() = %q, want empty", got)
	}
}

// TestNewRejectsNilStore 构造期 fail-fast：没有账户存储的控制面无意义。
func TestNewRejectsNilStore(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New without a store must fail")
	}
}

// seedUser 经控制面创建一个用户（正常路径前置）。
func seedUser(t *testing.T, ts *httptest.Server, username, password string) {
	t.Helper()
	code, body := doJSON(t, ts, http.MethodPost, "/users", map[string]string{"username": username, "password": password})
	if code != http.StatusCreated {
		t.Fatalf("seed user %s: got status %d, want 201 (body: %v)", username, code, body)
	}
}
