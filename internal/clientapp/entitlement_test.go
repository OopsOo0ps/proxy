package clientapp_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/clientapp"
	"github.com/OopsOo0ps/proxy/internal/config"
)

// —— 客户端 entitlement 门禁（迭代④，设计书 §3.1 客户端行 / §3.3 运行期行）——
//
// 客户端真相源 = 管理员分发的 entitlement 文件；门禁拒绝在线上与认证失败
// 同形（HTTP 407 / SOCKS5 失败码），且发生在握手期（零拨号）。

// gateUsers 是测试的复合凭据全集：三个用户都在入站静态凭据里，entitlement
// 文件里 alice=已过期、carol=无订阅、dave=有效（复用同一份文件跑门禁开/关
// 两种形态）。
var gateUsers = []struct{ user, pass string }{
	{"alice", "pw-alice"},
	{"carol", "pw-carol"},
	{"dave", "pw-dave"},
}

// writeEntitlementFile 写入管理员分发的 entitlement 文件（与账户库同一格式），
// 返回路径。aliceExpires 控制 alice 的订阅到期时刻。
func writeEntitlementFile(t *testing.T, dir string, aliceExpires time.Time) string {
	t.Helper()
	entry := func(name, password string, sub string) string {
		sum256 := sha256.Sum256([]byte(password))
		sum224 := sha256.Sum224([]byte(password))
		s := fmt.Sprintf(`{"username":%q,"password_sha256":%q,"password_sha224":%q,"status":"active"`,
			name, hex.EncodeToString(sum256[:]), hex.EncodeToString(sum224[:]))
		if sub != "" {
			s += `,"subscription":` + sub
		}
		return s + "}"
	}
	expired := fmt.Sprintf(`{"expires_at":%q,"granted_at":"2019-01-01T00:00:00Z"}`, aliceExpires.Format(time.RFC3339))
	valid := `{"expires_at":"2099-01-01T00:00:00Z","granted_at":"2019-01-01T00:00:00Z"}`
	doc := `{"version":1,"users":[` +
		entry("alice", "pw-alice", expired) + "," +
		entry("carol", "pw-carol", "") + "," +
		entry("dave", "pw-dave", valid) + `]}` + "\n"
	path := filepath.Join(dir, "entitlements.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// gateClientCfg 构造带静态凭据的客户端配置；gate=true 时叠加 gate+accounts
// （复合认证），否则行为与现状逐字一致。预热池关闭：每条请求一条新隧道，
// 「tunnel completed」记录即时可见（零拨号断言的确定性前提）。
func gateClientCfg(t *testing.T, node config.Node, entitlementPath string, gate bool) *config.Config {
	t.Helper()
	cfg := baseClientCfg([]config.Node{node})
	cfg.Outbound.Pool.Prewarm.Size = intPtr(0)
	for i := range cfg.Inbounds {
		users := make([]config.User, 0, len(gateUsers))
		for _, u := range gateUsers {
			users = append(users, config.User{Username: u.user, Password: u.pass})
		}
		cfg.Inbounds[i].Auth = &config.AuthConfig{Users: users}
	}
	if gate {
		cfg.Gate = &config.Gate{Enabled: true}
		cfg.Accounts = &config.Accounts{File: entitlementPath}
	}
	return cfg
}

// httpAuthStatus 以指定凭据经 HTTP 入站请求目标，返回状态码。
func httpAuthStatus(t *testing.T, app *clientapp.App, target, user, pass string) int {
	t.Helper()
	client := browser(t, fmt.Sprintf("http://%s:%s@%s", user, pass, app.HTTPAddr()), 1)
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET via proxy as %s: %v", user, err)
	}
	readBody(t, resp)
	return resp.StatusCode
}

func TestEntitlementGateRejectsWithoutDial(t *testing.T) {
	// 阶段一（零拨号，结构性证明）：出口节点是死地址（无监听者）。
	// 若门禁被绕过，请求会真正拨号并以 502/5xx 收场（拨号失败，见
	// TestE2EProxyWithoutNodesFails）；407 只可能来自认证层——静态凭据
	// 三人全部有效，唯一差异在订阅维度，被拒者必然从未出站。
	deadNode := trojanNode(t, "dead", "127.0.0.1:1", "node-secret")
	cfg := gateClientCfg(t, deadNode, "", true)
	dir := t.TempDir()
	cfg.Accounts.File = writeEntitlementFile(t, dir, time.Now().Add(-time.Hour)) // alice 已过期
	app := startClient(t, cfg, nil)
	target := startPlainTarget(t).URL

	for _, u := range []struct{ user, pass, why string }{
		{"alice", "pw-alice", "subscription expired"},
		{"carol", "pw-carol", "no subscription"},
		{"eve", "pw-alice", "not in entitlement"},
	} {
		if got := httpAuthStatus(t, app, target, u.user, u.pass); got != http.StatusProxyAuthRequired {
			t.Fatalf("%s (%s): status = %d, want 407 (must be denied at the auth layer, zero dial)", u.user, u.why, got)
		}
	}
	// 对照组：唯一通过门禁的 dave 真正走向拨号器（死节点 ⇒ 拨号失败 5xx，
	// 而非 407）——407/5xx 的分野就是「拒绝在握手期、零拨号」的证据。
	if got := httpAuthStatus(t, app, target, "dave", "pw-dave"); got < 500 {
		t.Fatalf("dave (valid subscription, dead node): status = %d, want >= 500 (dial must be attempted)", got)
	}

	// 阶段二（协议合法拒绝 + 全链路放行）：同一份 entitlement 文件配活节点。
	h := startServer(t, "node-secret", nil, false)
	live := gateClientCfg(t, trojanNode(t, "node-1", h.addr, "node-secret"), cfg.Accounts.File, true)
	liveApp := startClient(t, live, nil)
	for _, u := range []struct{ user, pass string }{
		{"alice", "pw-alice"},
		{"carol", "pw-carol"},
		{"eve", "pw-alice"},
	} {
		if got := httpAuthStatus(t, liveApp, target, u.user, u.pass); got != http.StatusProxyAuthRequired {
			t.Fatalf("%s: status = %d, want 407", u.user, got)
		}
	}
	if got := httpAuthStatus(t, liveApp, target, "dave", "pw-dave"); got != http.StatusOK {
		t.Fatalf("dave (valid subscription, live node): status = %d, want 200", got)
	}

	// SOCKS5 入站走同一复合认证器：无效订阅 = SOCKS5 认证失败码，有效订阅放行。
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	host, portString, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := socks5Dial(t, liveApp.SOCKS5Addr(), "alice", "pw-alice", host, uint16(port)); err == nil {
		t.Fatal("socks5 with an expired subscription must fail (authentication failure)")
	}
	conn, err := socks5Dial(t, liveApp.SOCKS5Addr(), "dave", "pw-dave", host, uint16(port))
	if err != nil {
		t.Fatalf("socks5 with a valid subscription: %v", err)
	}
	_ = conn.Close()
}

func TestEntitlementGateOffKeepsBehavior(t *testing.T) {
	// 门禁关（段缺省）：同一份过期/无订阅的 entitlement 文件躺在盘上但不被
	// 引用——行为与现状逐字一致，静态凭据命中即放行。
	h := startServer(t, "node-secret", nil, false)
	target := startPlainTarget(t)

	dir := t.TempDir()
	writeEntitlementFile(t, dir, time.Now().Add(-time.Hour))
	cfg := gateClientCfg(t, trojanNode(t, "node-1", h.addr, "node-secret"), "", false)
	app := startClient(t, cfg, nil)

	for _, u := range gateUsers {
		if got := httpAuthStatus(t, app, target.URL, u.user, u.pass); got != http.StatusOK {
			t.Fatalf("%s with gate off: status = %d, want 200 (behavior unchanged)", u.user, got)
		}
	}
}

func TestEntitlementStartupFailClosed(t *testing.T) {
	dir := t.TempDir()
	entPath := filepath.Join(dir, "entitlements.json")
	// 回环节点地址（Build 不拨号，地址仅需通过配置校验；insecure-skip-verify
	// 仅允许环回）。
	node := trojanNode(t, "node-1", "127.0.0.1:18443", "pw-1")

	// 门禁开 + 文件缺失：拒绝启动（fail-closed）。
	cfg := gateClientCfg(t, node, entPath, true)
	if _, err := clientapp.New(cfg, nil, nil); err == nil {
		t.Fatal("startup with a missing entitlement file must be refused")
	}

	// 门禁开 + 文件损坏：拒绝启动。
	if err := os.WriteFile(entPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := clientapp.New(cfg, nil, nil); err == nil {
		t.Fatal("startup with a corrupt entitlement file must be refused")
	}

	// 对照：同一配置去掉 gate/accounts（门禁关闭）即可构建——错误确属
	// entitlement 的 fail-closed，而非配置其他部分。
	off := gateClientCfg(t, node, "", false)
	rt, err := clientapp.Build(off, clientapp.BuildOptions{})
	if err != nil {
		t.Fatalf("same config without the gate must build: %v", err)
	}
	rt.Close()
}

func TestEntitlementReloadRebuildsView(t *testing.T) {
	h := startServer(t, "node-secret", nil, false)
	target := startPlainTarget(t)

	dir := t.TempDir()
	entPath := writeEntitlementFile(t, dir, time.Now().Add(-time.Hour)) // alice 过期
	cfgPath := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(cfgPath, []byte(entitlementClientYAML(h.addr, entPath)), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := config.Load(cfgPath, clientapp.KnownProtocols)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	app := startClient(t, parsed, nil)

	// 初始：alice 被门禁拒绝，dave 放行。
	if got := httpAuthStatus(t, app, target.URL, "alice", "pw-alice"); got != http.StatusProxyAuthRequired {
		t.Fatalf("alice before reload: status = %d, want 407", got)
	}
	if got := httpAuthStatus(t, app, target.URL, "dave", "pw-dave"); got != http.StatusOK {
		t.Fatalf("dave before reload: status = %d, want 200", got)
	}

	// 管理员续订（重写 entitlement 文件）+ SIGHUP：重载重建 entitlement 视图，
	// alice 立即放行。
	writeEntitlementFile(t, dir, time.Now().Add(24*time.Hour))
	if err := reloadWithPortRetry(t, app, cfgPath, ""); err != nil {
		t.Fatalf("reload after renewal: %v", err)
	}
	if got := httpAuthStatus(t, app, target.URL, "alice", "pw-alice"); got != http.StatusOK {
		t.Fatalf("alice after renewal reload: status = %d, want 200 (reload must rebuild the entitlement view)", got)
	}

	// 运行期坏文件：重载失败，旧运行时继续服务（上一份有效配置原样生效）。
	if err := os.WriteFile(entPath, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = reloadWithPortRetry(t, app, cfgPath, "")
	if err == nil {
		t.Fatal("reload with a corrupt entitlement file must fail")
	}
	if !strings.Contains(err.Error(), "entitlement") {
		t.Fatalf("reload error should name the entitlement file, got: %v", err)
	}
	if got := httpAuthStatus(t, app, target.URL, "alice", "pw-alice"); got != http.StatusOK {
		t.Fatalf("alice after failed reload: status = %d, want 200 (previous runtime keeps serving)", got)
	}
	if got := httpAuthStatus(t, app, target.URL, "dave", "pw-dave"); got != http.StatusOK {
		t.Fatalf("dave after failed reload: status = %d, want 200", got)
	}

	// 恢复文件后重载重新成功（旧配置的失败不留下任何残留状态）。
	writeEntitlementFile(t, dir, time.Now().Add(24*time.Hour))
	if err := reloadWithPortRetry(t, app, cfgPath, ""); err != nil {
		t.Fatalf("reload after repairing the file: %v", err)
	}
	if got := httpAuthStatus(t, app, target.URL, "alice", "pw-alice"); got != http.StatusOK {
		t.Fatalf("alice after repaired reload: status = %d, want 200", got)
	}
}

// entitlementClientYAML 是重载用例的客户端配置文档（含 gate + accounts 段，
// ReloadFile 每次从盘上重读——与 SIGHUP 路径一致）。
func entitlementClientYAML(nodeAddr, entPath string) string {
	return `gate:
  enabled: true
accounts:
  file: ` + strconv.Quote(entPath) + `
inbounds:
  - type: http
    listen: "127.0.0.1:0"
    auth:
      users:
        - { username: alice, password: pw-alice }
        - { username: carol, password: pw-carol }
        - { username: dave, password: pw-dave }
  - type: socks5
    listen: "127.0.0.1:0"
    auth:
      users:
        - { username: alice, password: pw-alice }
        - { username: carol, password: pw-carol }
        - { username: dave, password: pw-dave }
outbound:
  nodes:
    - name: node-1
      protocol: trojan
      params: { addr: "` + nodeAddr + `", password: "node-secret", insecure-skip-verify: true }
routing: { private-direct: false }
timeouts: { dial: 5s, handshake: 5s, idle: 30s, shutdown: 3s }
log: { level: info, format: json }
`
}
