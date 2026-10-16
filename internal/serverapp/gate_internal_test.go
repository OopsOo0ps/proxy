package serverapp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/accounts"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/testutil"
	"gopkg.in/yaml.v3"
)

// accountsCertParams 构造不带静态凭据的服务端 trojan 参数（accounts 模式：凭据
// 归动态账户库，静态 users 与之互斥；内部测试包无法复用 serverapp_test 助手）。
func accountsCertParams(t *testing.T, certFile, keyFile string) yaml.Node {
	t.Helper()
	body := "cert-file: " + strconv.Quote(certFile) + "\nkey-file: " + strconv.Quote(keyFile) + "\n"
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	return *doc.Content[0]
}

// gateTestStore 构建测试账户库：alice 启用 + 有效订阅（授予 = 起始时刻，到期
// +90 天），bob 停用，carol 启用 + 无订阅。返回 Store、起始时刻（时钟回拨
// 用例的基准）与可推进的假时钟。
func gateTestStore(t *testing.T) (*accounts.Store, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	if err := os.WriteFile(path, []byte("{\"version\":1,\"users\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := accounts.Open(path)
	if err != nil {
		t.Fatalf("accounts.Open: %v", err)
	}
	now := time.Now()
	st.Now = func() time.Time { return now }
	digests := func(pw string) (string, string) {
		s256 := sha256.Sum256([]byte(pw))
		s224 := sha256.Sum224([]byte(pw))
		return hex.EncodeToString(s256[:]), hex.EncodeToString(s224[:])
	}
	for _, u := range []struct{ name, pw string }{
		{"alice", "pw-alice"}, {"bob", "pw-bob"}, {"carol", "pw-carol"},
	} {
		sum256, sum224 := digests(u.pw)
		if err := st.Create(accounts.User{Username: u.name, PasswordSHA256: sum256, PasswordSHA224: sum224}); err != nil {
			t.Fatalf("Create %s: %v", u.name, err)
		}
	}
	if err := st.SetStatus("bob", accounts.StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSubscriptionExpiresAt("alice", now.Add(90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return st, &now
}

// tunnelHexOf 返回口令的 SHA-224 十六进制摘要（隧道反查口径）。
func tunnelHexOf(pw string) string {
	s := sha256.Sum224([]byte(pw))
	return hex.EncodeToString(s[:])
}

// entitlementSeriesOf 抓取 /metrics 原文（装饰器计数的断言口径：外部依赖
// client_golang 的属主只有 metrics 包，serverapp 不触达其测试工具）。
func entitlementSeriesOf(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

// TestCountingGateDecisions 单元测试决策计数器（设计书 §3.1 可观测性）：装饰器
// 在门禁决策点按 (decision, reason) 计数，全部存储期拒绝原因逐路径驱动，一次
// 判定恰好一次计数；返回值与视图逐字一致（拒绝仍返回匹配名）。
func TestCountingGateDecisions(t *testing.T) {
	st, now := gateTestStore(t)
	m := metrics.New(nil)
	g := countingGate{gate: st.Gate(true), m: m}

	// allow：有效订阅 ⇒ 放行 + allow/none。
	if name, ok := g.VerifyTunnel(tunnelHexOf("pw-alice")); !ok || name != "alice" {
		t.Fatalf("VerifyTunnel(alice) = %q, %v, want allow", name, ok)
	}
	// no_subscription：启用但无订阅。
	if name, ok := g.VerifyTunnel(tunnelHexOf("pw-carol")); ok || name != "carol" {
		t.Fatalf("VerifyTunnel(carol) = %q, %v, want deny with matched name", name, ok)
	}
	// disabled：停用用户（口令正确）。
	if name, ok := g.VerifyTunnel(tunnelHexOf("pw-bob")); ok || name != "bob" {
		t.Fatalf("VerifyTunnel(bob) = %q, %v, want deny with matched name", name, ok)
	}
	// unknown_user：摘要反查未命中。
	if name, ok := g.VerifyTunnel(strings.Repeat("0", 56)); ok || name != "" {
		t.Fatalf("VerifyTunnel(unknown) = %q, %v, want deny", name, ok)
	}
	// expired：时钟推进越过到期时刻。
	*now = now.Add(91 * 24 * time.Hour)
	if _, ok := g.VerifyTunnel(tunnelHexOf("pw-alice")); ok {
		t.Fatal("VerifyTunnel(alice) after expiry must be denied")
	}
	// clock_rollback：系统时刻早于授予时刻（回拨到订阅授予之前，fail-closed）。
	*now = now.Add(-200 * 24 * time.Hour)
	if _, ok := g.VerifyTunnel(tunnelHexOf("pw-alice")); ok {
		t.Fatal("VerifyTunnel(alice) on clock rollback must be denied")
	}

	body := entitlementSeriesOf(t, m)
	for _, want := range []string{
		`entitlement_decisions_total{decision="allow",reason="none"} 1`,
		`entitlement_decisions_total{decision="deny",reason="no_subscription"} 1`,
		`entitlement_decisions_total{decision="deny",reason="disabled"} 1`,
		`entitlement_decisions_total{decision="deny",reason="unknown_user"} 1`,
		`entitlement_decisions_total{decision="deny",reason="expired"} 1`,
		`entitlement_decisions_total{decision="deny",reason="clock_rollback"} 1`,
		// 未触发路径保持 0（有限枚举无序列空洞、无误计）。
		`entitlement_decisions_total{decision="deny",reason="bad_credentials"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics missing %q:\n%s", want, body)
		}
	}
}

// TestAssembleWiresGateView 组装根接线验收（设计书 §3.1）：accounts 模式构建
// 门禁视图作为隧道校验器，on = cfg.Gate.Enabled；gate 缺省/关闭 = 行为与现状
// 逐字一致（无订阅放行）；静态凭据模式不构建门禁。
func TestAssembleWiresGateView(t *testing.T) {
	// newCfg 构造 accounts 模式配置（TempDir 真实文件，环回 :0 免端口冲突）；
	// seed 在组装前向账户库写入无订阅用户 carol。
	newCfg := func(t *testing.T, gate *config.Gate) (*config.Config, string) {
		t.Helper()
		dir := t.TempDir()
		certFile, keyFile, err := testutil.WriteTLSCertFiles(dir)
		if err != nil {
			t.Fatal(err)
		}
		accountsPath := filepath.Join(dir, "accounts.json")
		if err := os.WriteFile(accountsPath, []byte("{\"version\":1,\"users\":[]}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return &config.Config{
			Inbounds: []config.Inbound{{
				Type:   config.TypeTrojan,
				Listen: "127.0.0.1:0",
				Params: accountsCertParams(t, certFile, keyFile),
			}},
			Accounts: &config.Accounts{File: accountsPath},
			Control:  &config.Control{Listen: "127.0.0.1:0"},
			Gate:     gate,
		}, accountsPath
	}
	seed := func(t *testing.T, path string) {
		t.Helper()
		st, err := accounts.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		s256 := sha256.Sum256([]byte("pw-carol"))
		s224 := sha256.Sum224([]byte("pw-carol"))
		if err := st.Create(accounts.User{
			Username:       "carol",
			PasswordSHA256: hex.EncodeToString(s256[:]),
			PasswordSHA224: hex.EncodeToString(s224[:]),
		}); err != nil {
			t.Fatal(err)
		}
	}
	assemble := func(t *testing.T, cfg *config.Config) *Runtime {
		t.Helper()
		var live atomic.Pointer[Runtime]
		b := newBuilder(BuildOptions{Metrics: metrics.New(nil)}, &live)
		rt, err := b.assemble(cfg)
		if err != nil {
			t.Fatalf("assemble: %v", err)
		}
		if rt.gate == nil {
			t.Fatal("accounts mode must build the gate verifier")
		}
		return rt
	}

	// 门禁缺省（nil 段）＝ 关闭：无订阅用户放行（与现状逐字一致）。
	cfg, accountsPath := newCfg(t, nil)
	seed(t, accountsPath)
	rt := assemble(t, cfg)
	if _, ok := rt.gate.VerifyTunnel(tunnelHexOf("pw-carol")); !ok {
		t.Fatal("gate absent: user without subscription must pass")
	}

	// 门禁开启：同一用户被拒（deny-by-default，生效边界 = 新握手判定）。
	cfg, accountsPath = newCfg(t, &config.Gate{Enabled: true})
	seed(t, accountsPath)
	rt = assemble(t, cfg)
	if _, ok := rt.gate.VerifyTunnel(tunnelHexOf("pw-carol")); ok {
		t.Fatal("gate enabled: user without subscription must be denied")
	}

	// 静态凭据模式（无 accounts 段）：不构建门禁，行为与现状一致。
	dir := t.TempDir()
	certFile, keyFile, err := testutil.WriteTLSCertFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	staticCfg := &config.Config{
		Inbounds: []config.Inbound{{
			Type:   config.TypeTrojan,
			Listen: "127.0.0.1:0",
			Params: trojanParams(t, certFile, keyFile, "alice", "secret"),
		}},
	}
	var live atomic.Pointer[Runtime]
	b := newBuilder(BuildOptions{Metrics: metrics.New(nil)}, &live)
	staticRT, err := b.assemble(staticCfg)
	if err != nil {
		t.Fatalf("assemble static: %v", err)
	}
	if staticRT.gate != nil {
		t.Fatal("static credential mode must not build the gate verifier")
	}
}
