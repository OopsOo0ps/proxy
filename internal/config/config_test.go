package config_test

import (
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/defaults"

	"gopkg.in/yaml.v3"
)

// clientProtocols / serverProtocols 与两个组装根的已知协议集一致。
var (
	clientProtocols = config.ProtocolSet{
		Inbounds: []string{config.TypeHTTP, config.TypeSOCKS5, config.TypeDNS},
		Outbound: []string{config.ProtocolTrojan},
	}
	serverProtocols = config.ProtocolSet{
		Inbounds: []string{config.TypeTrojan},
	}
)

func mustParse(t *testing.T, data string, ps config.ProtocolSet) config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(data), ps)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

func mustFail(t *testing.T, data string, ps config.ProtocolSet, want string) {
	t.Helper()
	_, err := config.Parse([]byte(data), ps)
	if err == nil {
		t.Fatalf("Parse must fail, want error containing %q", want)
	}
	if want != "" && !contains(err.Error(), want) {
		t.Fatalf("Parse error = %q, want containing %q", err.Error(), want)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

const minimalClient = `
inbounds:
  - type: http
    listen: "127.0.0.1:8080"
outbound:
  nodes:
    - name: edge-a
      protocol: trojan
      params: { addr: "vps.example.com:443", password: secret }
`

const minimalServer = `
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params:
      cert-file: server.crt
      key-file: server.key
      users: [{ username: alice, password: change-me }]
`

func TestParseMinimalClient(t *testing.T) {
	cfg := mustParse(t, minimalClient, clientProtocols)
	if len(cfg.Inbounds) != 1 || cfg.Inbounds[0].Type != config.TypeHTTP || cfg.Inbounds[0].Listen != "127.0.0.1:8080" {
		t.Fatalf("inbounds = %+v", cfg.Inbounds)
	}
	if cfg.Outbound == nil || len(cfg.Outbound.Nodes) != 1 {
		t.Fatalf("outbound = %+v", cfg.Outbound)
	}
	node := cfg.Outbound.Nodes[0]
	if node.Name != "edge-a" || node.Protocol != config.ProtocolTrojan || node.Weight != 0 {
		t.Fatalf("node = %+v", node)
	}
	var params struct {
		Addr     string
		Password string
	}
	if err := config.DecodeParams(node.Params, &params); err != nil {
		t.Fatalf("DecodeParams: %v", err)
	}
	if params.Addr != "vps.example.com:443" || params.Password != "secret" {
		t.Fatalf("params = %+v", params)
	}
	if cfg.Log.Level != defaults.LogLevel || cfg.Log.Format != defaults.LogFormat {
		t.Fatalf("log defaults not applied: %+v", cfg.Log)
	}
}

func TestParseMinimalServerRejectsOutboundAndRouting(t *testing.T) {
	mustParse(t, minimalServer, serverProtocols)
	mustFail(t, minimalServer+"\noutbound: { nodes: [] }\n", serverProtocols, "outbound: this binary has no outbound side")
	mustFail(t, minimalServer+"\nrouting: {}\n", serverProtocols, "routing: this binary has no routing side")
}

func TestParseClientRejectsTrojanInbound(t *testing.T) {
	mustFail(t, `
inbounds:
  - type: trojan
    listen: "127.0.0.1:8443"
`, clientProtocols, `unknown inbound type "trojan"`)
}

func TestUnknownFieldsFail(t *testing.T) {
	mustFail(t, minimalClient+"\nunknown_field: true\n", clientProtocols, "field unknown_field not found")
	mustFail(t, "inbounds: [{ type: http, listen: \"127.0.0.1:1\", bogus: 1 }]\noutbound: { nodes: [{ name: a, protocol: trojan }] }\n", clientProtocols, "field bogus not found")
}

func TestEmptyConfigFails(t *testing.T) {
	mustFail(t, "", clientProtocols, "config is empty")
}

func TestInboundEnvelopeValidation(t *testing.T) {
	mustFail(t, `
inbounds: []
`, clientProtocols, "at least one inbound must be configured")

	mustFail(t, `
inbounds:
  - type: http
    listen: ""
`, clientProtocols, "listen must not be empty")

	mustFail(t, `
inbounds:
  - type: http
    listen: "no-port"
`, clientProtocols, "invalid listen address")

	mustFail(t, `
inbounds:
  - type: http
    listen: "127.0.0.1:99999"
`, clientProtocols, "invalid port")

	// 非环回监听必须配置认证。
	mustFail(t, `
inbounds:
  - type: http
    listen: "0.0.0.0:8080"
`, clientProtocols, "requires auth")

	// 配置认证后通过。
	mustParse(t, `
inbounds:
  - type: http
    listen: "0.0.0.0:8080"
    auth:
      users: [{ username: alice, password: change-me }]
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols)

	// auth 通用检查：空用户名 / CRLF / 重复用户名。
	mustFail(t, `
inbounds:
  - type: http
    listen: "0.0.0.0:8080"
    auth: { users: [{ username: "", password: p }] }
`, clientProtocols, "username must not be empty")
	mustFail(t, `
inbounds:
  - type: http
    listen: "0.0.0.0:8080"
    auth: { users: [{ username: a, password: "p\r\nx" }] }
`, clientProtocols, "must not contain CR or LF")
	mustFail(t, `
inbounds:
  - type: http
    listen: "0.0.0.0:8080"
    auth: { users: [{ username: a, password: p }, { username: a, password: q }] }
`, clientProtocols, "duplicate username")
}

func TestDNSInboundRequiresLoopbackAndNoAuth(t *testing.T) {
	mustFail(t, `
inbounds:
  - type: dns
    listen: "0.0.0.0:53"
`, clientProtocols, "open resolver")
	mustFail(t, `
inbounds:
  - type: dns
    listen: "127.0.0.1:53"
    auth: { users: [{ username: a, password: p }] }
`, clientProtocols, "does not support auth")
}

func TestListenPortConflictDetection(t *testing.T) {
	mustFail(t, `
inbounds:
  - type: http
    listen: "127.0.0.1:8080"
  - type: socks5
    listen: "127.0.0.1:8080"
`, clientProtocols, "conflicts")

	// 通配地址与具体地址同端口冲突。
	mustFail(t, `
api: { listen: "0.0.0.0:9100", allow-remote: true }
inbounds:
  - type: http
    listen: "127.0.0.1:9100"
`, clientProtocols, "conflicts")

	// 不同端口不冲突；端口 0 不参与。
	mustParse(t, `
inbounds:
  - type: http
    listen: "127.0.0.1:8080"
  - type: socks5
    listen: "127.0.0.1:0"
  - type: dns
    listen: "127.0.0.1:53"
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols)
}

func TestNodeEnvelopeValidation(t *testing.T) {
	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound:
  nodes:
    - name: ""
      protocol: trojan
`, clientProtocols, "name must not be empty")

	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound:
  nodes:
    - name: a
      protocol: trojan
    - name: a
      protocol: trojan
`, clientProtocols, "duplicate node name")

	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound:
  nodes:
    - name: a
      protocol: shadowsocks
`, clientProtocols, `unknown protocol "shadowsocks"`)

	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound:
  nodes:
    - name: a
      protocol: trojan
      weight: -1
`, clientProtocols, "weight must not be negative")
}

func TestPoolEnvelopeValidation(t *testing.T) {
	base := `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound:
  nodes:
    - name: a
      protocol: trojan
  pool:
`
	mustFail(t, base+"    prewarm: { size: -1 }\n", clientProtocols, "prewarm.size")
	mustFail(t, base+"    prewarm: { ttl: -1s }\n", clientProtocols, "prewarm.ttl")
	mustFail(t, base+"    health: { failures: 0 }\n", clientProtocols, "health.failures")
	mustFail(t, base+"    health: { successes: 0 }\n", clientProtocols, "health.successes")
	mustFail(t, base+"    health: { interval: -1s }\n", clientProtocols, "health.interval")
	mustFail(t, base+"    failover-budget: -1s\n", clientProtocols, "failover-budget")
}

func TestRoutingRuleVocabulary(t *testing.T) {
	cfg := mustParse(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound:
  nodes: [{ name: a, protocol: trojan }]
routing:
  rules:
    - { match: domain-suffix, value: cn, action: direct }
    - { match: cidr, value: 10.0.0.0/8, action: proxy }
    - { match: ip, value: 1.2.3.4, action: reject }
    - { match: domain, value: example.com, action: direct }
    - { default: proxy }
`, clientProtocols)
	rules := cfg.Routing.Rules
	if len(rules) != 5 {
		t.Fatalf("rules = %+v", rules)
	}
	r0, err := rules[0].RoutingRule()
	if err != nil {
		t.Fatal(err)
	}
	if r0.Match[0] != "*.cn" || r0.Action != core.RouteDirect {
		t.Fatalf("rule0 = %+v", r0)
	}
	r2, err := rules[2].RoutingRule()
	if err != nil {
		t.Fatal(err)
	}
	if r2.Action != core.RouteReject {
		t.Fatalf("reject rule = %+v", r2)
	}
	if rules[4].Default == nil || *rules[4].Default != core.RouteProxy {
		t.Fatalf("default rule = %+v", rules[4])
	}

	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound: { nodes: [{ name: a, protocol: trojan }] }
routing:
  rules:
    - { match: regex, value: x, action: direct }
`, clientProtocols, "unknown match")

	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound: { nodes: [{ name: a, protocol: trojan }] }
routing:
  rules:
    - { match: domain-suffix, value: "bad/wild", action: direct }
`, clientProtocols, "wildcard")

	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound: { nodes: [{ name: a, protocol: trojan }] }
routing:
  rules:
    - { match: cidr, value: "10.0.0.0/99", action: direct }
`, clientProtocols, "cidr")

	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound: { nodes: [{ name: a, protocol: trojan }] }
routing:
  rules:
    - { match: ip, value: "not-an-ip", action: direct }
`, clientProtocols, "ip")

	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound: { nodes: [{ name: a, protocol: trojan }] }
routing:
  rules:
    - { match: domain-suffix, value: cn, action: drop }
`, clientProtocols, "invalid routing action")

	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound: { nodes: [{ name: a, protocol: trojan }] }
routing:
  rules:
    - { default: proxy, match: domain, value: x, action: direct }
`, clientProtocols, "must not be combined")

	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound: { nodes: [{ name: a, protocol: trojan }] }
routing:
  rules:
    - { match: domain }
`, clientProtocols, "requires match, value and action")
}

func TestProxyWithoutExitNodesFails(t *testing.T) {
	// 缺省动作 proxy + 零节点：解析期拒绝。
	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
`, clientProtocols, "at least one exit node is required")

	// 全部 direct 的客户端允许零节点。
	mustParse(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
routing:
  rules:
    - { default: direct }
`, clientProtocols)

	// 含 proxy 规则 + 零节点：拒绝。
	mustFail(t, `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
routing:
  rules:
    - { default: direct }
    - { match: domain-suffix, value: cn, action: proxy }
`, clientProtocols, "at least one exit node is required")
}

func TestRulesetsValidation(t *testing.T) {
	base := `
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound: { nodes: [{ name: a, protocol: trojan }] }
routing:
  rulesets:
`
	mustFail(t, base+"    - { name: \"\", url: \"https://example.com/rules\" }\n", clientProtocols, "name must not be empty")
	mustFail(t, base+"    - { name: a, url: \"ftp://example.com/rules\" }\n", clientProtocols, "unsupported scheme")
	mustFail(t, base+"    - { name: a, url: \"https://example.com/rules\", path: x.yaml }\n", clientProtocols, "path is not allowed")
	mustFail(t, base+"    - { name: a, type: file }\n", clientProtocols, "path must not be empty")
	mustFail(t, base+"    - { name: a, type: file, path: rules.yaml, interval: 5m }\n", clientProtocols, "interval only applies")
	mustFail(t, base+"    - { name: a, url: \"https://example.com/rules\", interval: 0s }\n", clientProtocols, "must be positive")
	mustFail(t, base+"    - { name: a, type: git, url: x }\n", clientProtocols, "unknown type")
	mustFail(t, base+`    - { name: a, url: "https://example.com/rules" }
    - { name: b, type: file, path: rules.yaml }
`, clientProtocols, "at most one rule source")

	// type 省缺 url；interval 省缺 defaults。
	cfg := mustParse(t, base+"    - { name: cn-list, url: \"https://example.com/rules.yaml\" }\n", clientProtocols)
	rs := cfg.Routing.Rulesets[0]
	if rs.EffectiveInterval() != defaults.RulesetRefreshInterval {
		t.Fatalf("ruleset interval = %v", rs.EffectiveInterval())
	}
}

func TestRoutingDNSValidation(t *testing.T) {
	base := `
inbounds:
  - type: dns
    listen: "127.0.0.1:53"
  - type: http
    listen: "127.0.0.1:8080"
outbound: { nodes: [{ name: a, protocol: trojan }] }
routing:
  dns:
`
	mustFail(t, base+"    remote: \"no-port\"\n", clientProtocols, "invalid address")
	mustFail(t, base+"    local: [\"127.0.0.1:53\"]\n", clientProtocols, "points to the DNS gateway itself")
	mustFail(t, base+"    timeout: -1s\n", clientProtocols, "must not be negative")

	cfg := mustParse(t, base+"    remote: \"9.9.9.9:53\"\n", clientProtocols)
	if got := cfg.Routing.DNS.EffectiveRemote(); got != "9.9.9.9:53" {
		t.Fatalf("remote = %q", got)
	}
	// 未配置 remote 时取 defaults（与 dnsgw 同源）。
	cfg2 := mustParse(t, base+"    local: [\"192.168.1.1:53\"]\n", clientProtocols)
	if got := cfg2.Routing.DNS.EffectiveRemote(); got != defaults.DNSRemote {
		t.Fatalf("remote default = %q", got)
	}
	if got := cfg2.Routing.DNS.EffectiveTimeout(); got != defaults.DNSTimeout {
		t.Fatalf("timeout default = %q", got)
	}
}

func TestAPIAndLogValidation(t *testing.T) {
	mustFail(t, `
api: { listen: "0.0.0.0:9100" }
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols, "api.allow-remote")

	mustParse(t, `
api: { listen: "0.0.0.0:9100", allow-remote: true }
inbounds: [{ type: http, listen: "127.0.0.1:8080" }]
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols)

	mustFail(t, minimalClient+"\nlog: { level: verbose }\n", clientProtocols, "log.level")
	mustFail(t, minimalClient+"\nlog: { format: xml }\n", clientProtocols, "log.format")
}

func TestTimeoutsAndLimits(t *testing.T) {
	mustFail(t, minimalClient+"\ntimeouts: { dial: -1s }\n", clientProtocols, "timeouts.dial")
	mustFail(t, minimalClient+"\ntimeouts: { shutdown: -5s }\n", clientProtocols, "timeouts.shutdown")
	mustFail(t, minimalClient+"\nlimits: { max-connections: -1 }\n", clientProtocols, "limits.max-connections")

	cfg := mustParse(t, minimalClient+"\ntimeouts: { dial: 3s, handshake: 4s, idle: 60s, shutdown: 7s }\n", clientProtocols)
	if got := cfg.Timeouts.EffectiveDial(); got != 3*time.Second {
		t.Fatalf("dial = %v", got)
	}
	if got := cfg.Timeouts.EffectiveShutdown(); got != 7*time.Second {
		t.Fatalf("shutdown = %v", got)
	}
	// 缺省与 internal/defaults 同源。
	empty := mustParse(t, minimalClient, clientProtocols)
	if empty.Timeouts.EffectiveDial() != defaults.DialTimeout ||
		empty.Timeouts.EffectiveHandshake() != defaults.HandshakeTimeout ||
		empty.Timeouts.EffectiveIdle() != defaults.IdleTimeout ||
		empty.Timeouts.EffectiveShutdown() != defaults.DrainTimeout {
		t.Fatalf("timeout defaults mismatch: %+v", empty.Timeouts)
	}
	if got := empty.Outbound.Pool.EffectiveFailoverBudget(); got != defaults.FailoverBudget {
		t.Fatalf("failover budget default = %v", got)
	}
	if empty.Limits.EffectiveMaxConnections() != defaults.MaxConnections {
		t.Fatalf("max connections default = %d", empty.Limits.EffectiveMaxConnections())
	}
}

func TestDecodeParamsStrict(t *testing.T) {
	// 未知字段报错（KnownFields(true)）。
	data := `
params:
  addr: "vps.example.com:443"
  password: secret
  bogus: 1
`
	var doc struct {
		Params yaml.Node `yaml:"params"`
	}
	if err := yaml.Unmarshal([]byte(data), &doc); err != nil {
		t.Fatal(err)
	}
	var p struct {
		Addr     string
		Password string
	}
	if err := config.DecodeParams(doc.Params, &p); err == nil {
		t.Fatal("unknown params field must fail")
	}

	// 字段缺省 / 显式 null：保持零值、不报错。
	if err := config.DecodeParams(yaml.Node{}, &p); err != nil {
		t.Fatalf("zero node: %v", err)
	}
	var nullDoc struct {
		Params yaml.Node `yaml:"params"`
	}
	if err := yaml.Unmarshal([]byte("params:\n"), &nullDoc); err != nil {
		t.Fatal(err)
	}
	if err := config.DecodeParams(nullDoc.Params, &p); err != nil {
		t.Fatalf("null params: %v", err)
	}

	// 非映射报用户可读错误。
	var scalar struct {
		Params yaml.Node `yaml:"params"`
	}
	if err := yaml.Unmarshal([]byte("params: just-a-string\n"), &scalar); err != nil {
		t.Fatal(err)
	}
	if err := config.DecodeParams(scalar.Params, &p); err == nil {
		t.Fatal("scalar params must fail")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := config.Load(t.TempDir()+"/missing.yaml", clientProtocols); err == nil {
		t.Fatal("missing file must fail")
	}
}

func TestUpstreamFingerprint(t *testing.T) {
	a := mustParse(t, minimalClient, clientProtocols)
	b := mustParse(t, minimalClient, clientProtocols)

	fa, err := config.UpstreamFingerprint(&a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := config.UpstreamFingerprint(&b)
	if err != nil {
		t.Fatal(err)
	}
	if fa != fb {
		t.Fatal("identical configs must produce identical fingerprints")
	}

	// 上游相关字段变化 → 指纹变化。
	c := mustParse(t, minimalClient+"\ntimeouts: { dial: 4s }\n", clientProtocols)
	fc, err := config.UpstreamFingerprint(&c)
	if err != nil {
		t.Fatal(err)
	}
	if fa == fc {
		t.Fatal("timeout change must change the fingerprint")
	}

	// params 内注释 / 排版差异 → 指纹不变（规范化）。
	withComments := mustParse(t, `
inbounds:
  - type: http
    listen: "127.0.0.1:8080"   # 入站
outbound:
  nodes:
    - name: edge-a
      protocol: trojan
      # 出口节点
      params:
        addr: "vps.example.com:443"
        password: secret
`, clientProtocols)
	fd, err := config.UpstreamFingerprint(&withComments)
	if err != nil {
		t.Fatal(err)
	}
	if fa != fd {
		t.Fatal("comment/formatting-only differences must not change the fingerprint")
	}
}
