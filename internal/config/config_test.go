package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const validClientYAML = `
inbound:
  http: "127.0.0.1:8080"
  socks5: "127.0.0.1:1080"
  auth:
    - username: alice
      password: change-me
nodes:
  - addr: "node1.example.com:443"
    password: node1-token
    sni: www.example.com
  - addr: "node2.example.com:443"
    password: node2-token
  - addr: "node3.example.com:443"
    password: node3-token
routing:
  default: proxy
  rules_file: rules.yaml
metrics:
  listen: "127.0.0.1:9100"
log:
  level: debug
  format: text
timeouts:
  dial: 5s
  handshake: 8s
  idle: 60s
tls:
  ca_file: ca.pem
`

func TestParseClientValid(t *testing.T) {
	cfg, err := ParseClient([]byte(validClientYAML))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if cfg.Inbound.HTTP != "127.0.0.1:8080" || cfg.Inbound.SOCKS5 != "127.0.0.1:1080" {
		t.Fatalf("unexpected inbound: %+v", cfg.Inbound)
	}
	if len(cfg.Nodes) != 3 {
		t.Fatalf("nodes = %d, want 3", len(cfg.Nodes))
	}
	if cfg.Nodes[0].SNI != "www.example.com" {
		t.Fatalf("node sni = %q", cfg.Nodes[0].SNI)
	}
	if cfg.Timeouts.Dial.Std() != 5*time.Second {
		t.Fatalf("dial timeout = %v, want 5s", cfg.Timeouts.Dial.Std())
	}
	if cfg.Timeouts.Shutdown.Std() != 15*time.Second {
		t.Fatalf("default shutdown timeout = %v, want 15s", cfg.Timeouts.Shutdown.Std())
	}
	if cfg.TLS.CAFile != "ca.pem" {
		t.Fatalf("ca_file = %q", cfg.TLS.CAFile)
	}
}

func TestParseClientDefaults(t *testing.T) {
	cfg, err := ParseClient([]byte(`
inbound:
  http: ":8080"
  auth:
    - username: alice
      password: change-me
nodes:
  - addr: "node1.example.com:443"
    password: token
`))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if cfg.Timeouts.Dial.Std() != 10*time.Second {
		t.Fatalf("default dial = %v, want 10s", cfg.Timeouts.Dial.Std())
	}
	if cfg.Timeouts.Handshake.Std() != 10*time.Second {
		t.Fatalf("default handshake = %v, want 10s", cfg.Timeouts.Handshake.Std())
	}
	if cfg.Timeouts.Idle.Std() != 90*time.Second {
		t.Fatalf("default idle = %v, want 90s", cfg.Timeouts.Idle.Std())
	}
	if cfg.Routing.Default != "proxy" {
		t.Fatalf("default routing = %q, want proxy", cfg.Routing.Default)
	}
	if cfg.Routing.PrivateDirect == nil || !*cfg.Routing.PrivateDirect {
		t.Fatal("private_direct should default to true")
	}
	if cfg.Log.Level != "info" || cfg.Log.Format != "json" {
		t.Fatalf("default log = %+v, want info/json", cfg.Log)
	}
	if got := cfg.Pool.EffectiveMaxIdle(); got != 2 {
		t.Fatalf("default pool.max_idle = %d, want 2", got)
	}
	if got := cfg.Pool.EffectiveIdleTTL(); got != 5*time.Second {
		t.Fatalf("default pool.idle_ttl = %v, want 5s", got)
	}
}

func TestParseClientPoolOverrides(t *testing.T) {
	base := `
inbound:
  http: "127.0.0.1:8080"
nodes:
  - addr: "node1.example.com:443"
    password: token
`
	// 显式配置生效。
	cfg, err := ParseClient([]byte(base + `
pool:
  max_idle: 4
  idle_ttl: 2s
`))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if got := cfg.Pool.EffectiveMaxIdle(); got != 4 {
		t.Fatalf("pool.max_idle = %d, want 4", got)
	}
	if got := cfg.Pool.EffectiveIdleTTL(); got != 2*time.Second {
		t.Fatalf("pool.idle_ttl = %v, want 2s", got)
	}

	// 显式关闭：max_idle = 0 不会被默认值覆盖。
	cfg, err = ParseClient([]byte(base + `
pool:
  max_idle: 0
`))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if got := cfg.Pool.EffectiveMaxIdle(); got != 0 {
		t.Fatalf("pool.max_idle = %d, want 0（显式关闭）", got)
	}
}

func TestParseClientRejectsBadPool(t *testing.T) {
	base := `
inbound:
  http: "127.0.0.1:8080"
nodes:
  - addr: "node1.example.com:443"
    password: token
`
	cases := map[string]string{
		"negative max_idle": base + "pool:\n  max_idle: -1\n",
		"negative idle_ttl": base + "pool:\n  idle_ttl: -1s\n",
		"unknown pool key":  base + "pool:\n  max_idle2: 1\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseClient([]byte(yaml)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseClientDurationSecondsFallback(t *testing.T) {
	cfg, err := ParseClient([]byte(`
inbound:
  http: "127.0.0.1:8080"
nodes:
  - addr: "node1.example.com:443"
    password: token
timeouts:
  dial: 30
`))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if cfg.Timeouts.Dial.Std() != 30*time.Second {
		t.Fatalf("dial = %v, want 30s", cfg.Timeouts.Dial.Std())
	}
}

func TestParseClientShutdownTimeout(t *testing.T) {
	base := `
inbound:
  http: "127.0.0.1:8080"
nodes:
  - addr: "node1.example.com:443"
    password: token
`
	cfg, err := ParseClient([]byte(base + "timeouts:\n  shutdown: 3s\n"))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if cfg.Timeouts.Shutdown.Std() != 3*time.Second {
		t.Fatalf("shutdown = %v, want 3s", cfg.Timeouts.Shutdown.Std())
	}
}

func TestParseClientLimits(t *testing.T) {
	base := `
inbound:
  http: "127.0.0.1:8080"
nodes:
  - addr: "node1.example.com:443"
    password: token
`
	cfg, err := ParseClient([]byte(base))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if got := cfg.Limits.EffectiveMaxConnections(); got != 1024 {
		t.Fatalf("default max_connections = %d, want 1024", got)
	}

	cfg, err = ParseClient([]byte(base + "limits:\n  max_connections: 8\n"))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if got := cfg.Limits.EffectiveMaxConnections(); got != 8 {
		t.Fatalf("max_connections = %d, want 8", got)
	}

	cfg, err = ParseClient([]byte(base + "limits:\n  max_connections: 0\n"))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if got := cfg.Limits.EffectiveMaxConnections(); got != 0 {
		t.Fatalf("max_connections = %d, want 0（显式不限制）", got)
	}
}

func TestParseClientRejects(t *testing.T) {
	cases := map[string]string{
		"empty config":         ``,
		"unknown field":        "inbound:\n  http: \"127.0.0.1:8080\"\nbogus: true\n",
		"no inbound":           "nodes:\n  - addr: \"n.example.com:443\"\n    password: t\n",
		"bad listen addr":      "inbound:\n  http: \"127.0.0.1\"\n",
		"bad listen port":      "inbound:\n  http: \"127.0.0.1:99999\"\n",
		"non-loopback no auth": "inbound:\n  socks5: \"0.0.0.0:1080\"\n",
		"no nodes proxy":       "inbound:\n  http: \"127.0.0.1:8080\"\n",
		"bad node addr":        "inbound:\n  http: \"127.0.0.1:8080\"\nnodes:\n  - addr: \"n.example.com\"\n    password: t\n",
		"node empty password":  "inbound:\n  http: \"127.0.0.1:8080\"\nnodes:\n  - addr: \"n.example.com:443\"\n    password: \"\"\n",
		"node crlf password":   "inbound:\n  http: \"127.0.0.1:8080\"\nnodes:\n  - addr: \"n.example.com:443\"\n    password: \"a\\nb\"\n",
		"bad routing action":   "inbound:\n  http: \"127.0.0.1:8080\"\nrouting:\n  default: tunnel\n",
		"bad log level":        "inbound:\n  http: \"127.0.0.1:8080\"\nlog:\n  level: verbose\n",
		"bad log format":       "inbound:\n  http: \"127.0.0.1:8080\"\nlog:\n  format: xml\n",
		"bad duration":         "inbound:\n  http: \"127.0.0.1:8080\"\ntimeouts:\n  dial: fast\n",
		"zero duration":        "inbound:\n  http: \"127.0.0.1:8080\"\ntimeouts:\n  dial: 0s\n",
		"negative shutdown":    "inbound:\n  http: \"127.0.0.1:8080\"\ntimeouts:\n  shutdown: -1s\n",
		"negative conn limit":  "inbound:\n  http: \"127.0.0.1:8080\"\nlimits:\n  max_connections: -1\n",
		"duplicate user":       "inbound:\n  http: \"127.0.0.1:8080\"\n  auth:\n    - username: a\n      password: 1\n    - username: a\n      password: 2\n",
		"metrics bad addr":     "inbound:\n  http: \"127.0.0.1:8080\"\nmetrics:\n  listen: \"127.0.0.1\"\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseClient([]byte(yaml)); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestParseClientDirectOnlyAllowsNoNodes(t *testing.T) {
	cfg, err := ParseClient([]byte(`
inbound:
  http: "127.0.0.1:8080"
routing:
  default: direct
`))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if cfg.Routing.Default != "direct" {
		t.Fatalf("routing default = %q", cfg.Routing.Default)
	}
}

func TestParseClientDNSGateway(t *testing.T) {
	cfg, err := ParseClient([]byte(`
inbound:
  http: "127.0.0.1:8080"
nodes:
  - addr: "node1.example.com:443"
    password: token
dns:
  listen: "127.0.0.1:1053"
`))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if cfg.DNS.EffectiveRemote() != "1.1.1.1:53" {
		t.Fatalf("default remote = %q, want 1.1.1.1:53", cfg.DNS.EffectiveRemote())
	}
	if cfg.DNS.EffectiveTimeout() != 5*time.Second {
		t.Fatalf("default timeout = %v, want 5s", cfg.DNS.EffectiveTimeout())
	}

	cfg, err = ParseClient([]byte(`
inbound:
  http: "127.0.0.1:8080"
nodes:
  - addr: "node1.example.com:443"
    password: token
dns:
  listen: "127.0.0.1:1053"
  remote: "223.5.5.5:53"
  local: ["192.168.1.1:53", "[::1]:53"]
  timeout: 2s
`))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if cfg.DNS.Remote != "223.5.5.5:53" || len(cfg.DNS.Local) != 2 || cfg.DNS.EffectiveTimeout() != 2*time.Second {
		t.Fatalf("unexpected dns config: %+v", cfg.DNS)
	}
}

func TestParseClientDNSRejects(t *testing.T) {
	// 除 dns 段外均为合法配置，确保报错确实来自 dns 校验。
	prefix := "inbound:\n  http: \"127.0.0.1:8080\"\nnodes:\n  - addr: \"n.example.com:443\"\n    password: t\n"
	cases := map[string]string{
		"stray dns field":         prefix + "dns:\n  remote: \"8.8.8.8:53\"\n",
		"stray dns timeout":       prefix + "dns:\n  timeout: 3s\n",
		"non-loopback dns listen": prefix + "dns:\n  listen: \"0.0.0.0:53\"\n",
		"empty-host dns listen":   prefix + "dns:\n  listen: \":53\"\n",
		"bad dns listen":          prefix + "dns:\n  listen: \"127.0.0.1\"\n",
		"bad dns remote":          prefix + "dns:\n  listen: \"127.0.0.1:1053\"\n  remote: \"8.8.8.8\"\n",
		"bad dns local":           prefix + "dns:\n  listen: \"127.0.0.1:1053\"\n  local: [\"8.8.8.8\"]\n",
		"dns local is self":       prefix + "dns:\n  listen: \"127.0.0.1:1053\"\n  local: [\"127.0.0.1:1053\"]\n",
		"dns unknown field":       prefix + "dns:\n  listen: \"127.0.0.1:1053\"\n  fake_ip: true\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseClient([]byte(yaml)); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestParseServerValid(t *testing.T) {
	cfg, err := ParseServer([]byte(`
listen: "0.0.0.0:8443"
tls:
  cert_file: /etc/proxy/server.crt
  key_file: /etc/proxy/server.key
users:
  - username: alice
    password: token-1
  - username: bob
    password: token-2
decoy_file: /etc/proxy/decoy.html
metrics:
  listen: "127.0.0.1:9200"
`))
	if err != nil {
		t.Fatalf("ParseServer: %v", err)
	}
	if len(cfg.Users) != 2 {
		t.Fatalf("users = %d, want 2", len(cfg.Users))
	}
	if cfg.Timeouts.Idle.Std() != 90*time.Second {
		t.Fatalf("default idle = %v", cfg.Timeouts.Idle.Std())
	}
	if cfg.Timeouts.Shutdown.Std() != 15*time.Second {
		t.Fatalf("default shutdown = %v, want 15s", cfg.Timeouts.Shutdown.Std())
	}
	if cfg.Limits.EffectiveMaxConnections() != 1024 {
		t.Fatalf("default max_connections = %d, want 1024", cfg.Limits.EffectiveMaxConnections())
	}
	if cfg.Log.Format != "json" {
		t.Fatalf("default log format = %q", cfg.Log.Format)
	}
}

func TestParseServerRejects(t *testing.T) {
	base := `
listen: "0.0.0.0:8443"
tls:
  cert_file: cert.pem
  key_file: key.pem
users:
  - username: alice
    password: token
`
	cases := map[string]string{
		"missing listen":  "tls:\n  cert_file: c\n  key_file: k\nusers:\n  - {username: a, password: b}\n",
		"missing tls":     "listen: \":8443\"\nusers:\n  - {username: a, password: b}\n",
		"missing users":   "listen: \":8443\"\ntls:\n  cert_file: c\n  key_file: k\n",
		"empty user name": "listen: \":8443\"\ntls:\n  cert_file: c\n  key_file: k\nusers:\n  - {username: \"\", password: b}\n",
		"empty password":  "listen: \":8443\"\ntls:\n  cert_file: c\n  key_file: k\nusers:\n  - {username: a, password: \"\"}\n",
		"unknown field":   base + "cache: true\n",
		"invalid listen":  "listen: \"nope\"\ntls:\n  cert_file: c\n  key_file: k\nusers:\n  - {username: a, password: b}\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseServer([]byte(yaml)); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestLoadClientFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(path, []byte(validClientYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if len(cfg.Nodes) != 3 {
		t.Fatalf("nodes = %d, want 3", len(cfg.Nodes))
	}

	if _, err := LoadClient(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadServerWrapsPathInError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("listen: [1,2]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadServer(path)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error should mention config path, got %v", err)
	}
}

func TestIsLoopbackListen(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080":    true,
		"[::1]:8080":        true,
		"localhost:8080":    true,
		"0.0.0.0:8080":      false,
		":8080":             false,
		"192.168.1.10:8080": false,
	}
	for addr, want := range cases {
		if got := isLoopbackListen(addr); got != want {
			t.Fatalf("isLoopbackListen(%q) = %v, want %v", addr, got, want)
		}
	}
}

// TestShippedExampleConfigsParse 保证仓库内示例配置始终可解析，
// 防止文档与实现漂移。
func TestShippedExampleConfigsParse(t *testing.T) {
	clientConfigs := []string{
		"../../configs/example-client.yaml",
		"../../configs/local/client.yaml",
	}
	for _, path := range clientConfigs {
		if _, err := LoadClient(path); err != nil {
			t.Errorf("LoadClient(%s): %v", path, err)
		}
	}

	serverConfigs := []string{
		"../../configs/example-server.yaml",
		"../../configs/local/server-1.yaml",
		"../../configs/local/server-2.yaml",
		"../../configs/local/server-3.yaml",
	}
	for _, path := range serverConfigs {
		if _, err := LoadServer(path); err != nil {
			t.Errorf("LoadServer(%s): %v", path, err)
		}
	}
}

func TestClientRestartOnlyChanges(t *testing.T) {
	base := func(t *testing.T) *Client {
		t.Helper()
		cfg, err := ParseClient([]byte(validClientYAML))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	if got := ClientRestartOnlyChanges(base(t), base(t)); len(got) != 0 {
		t.Fatalf("identical configs reported restart-only fields: %v", got)
	}

	// 可热加载字段的变更（凭据 / 节点 / 分流 / 超时 / 日志 / 连接上限）不要求重启。
	hot := base(t)
	hot.Inbound.Auth = []User{{Username: "bob", Password: "pw"}}
	hot.Nodes = hot.Nodes[:1]
	hot.Routing.Default = "direct"
	hot.Routing.RulesFile = "other-rules.yaml"
	hot.Pool.MaxIdle = intPtr(4)
	hot.Limits.MaxConnections = intPtr(10)
	hot.Timeouts.Dial = Duration(3 * time.Second)
	hot.Log.Level = "info"
	hot.TLS.InsecureSkipVerify = true
	if got := ClientRestartOnlyChanges(base(t), hot); len(got) != 0 {
		t.Fatalf("hot-reloadable changes reported as restart-only: %v", got)
	}

	// 监听地址的变更要求重启。
	addrs := base(t)
	addrs.Inbound.HTTP = "127.0.0.1:18080"
	addrs.Inbound.SOCKS5 = "127.0.0.1:11080"
	addrs.Metrics.Listen = "127.0.0.1:19100"
	addrs.DNS.Listen = "127.0.0.1:1053"
	want := []string{"inbound.http", "inbound.socks5", "metrics.listen", "dns.listen"}
	if got := ClientRestartOnlyChanges(base(t), addrs); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart-only fields = %v, want %v", got, want)
	}
}

func TestServerRestartOnlyChanges(t *testing.T) {
	base := func(t *testing.T) *Server {
		t.Helper()
		cfg, err := ParseServer([]byte(`
listen: "0.0.0.0:8443"
tls: { cert_file: server.crt, key_file: server.key }
users:
  - { username: alice, password: change-me }
metrics: { listen: "127.0.0.1:9200" }
`))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	if got := ServerRestartOnlyChanges(base(t), base(t)); len(got) != 0 {
		t.Fatalf("identical configs reported restart-only fields: %v", got)
	}

	// 可热加载字段：凭据 / 证书文件 / 伪装页 / 超时 / 日志 / 连接上限。
	hot := base(t)
	hot.Users = []User{{Username: "bob", Password: "pw"}}
	hot.TLS.CertFile = "new-server.crt"
	hot.DecoyFile = "decoy.html"
	hot.Limits.MaxConnections = intPtr(10)
	hot.Timeouts.Idle = Duration(30 * time.Second)
	hot.Log.Level = "debug"
	if got := ServerRestartOnlyChanges(base(t), hot); len(got) != 0 {
		t.Fatalf("hot-reloadable changes reported as restart-only: %v", got)
	}

	restart := base(t)
	restart.Listen = "0.0.0.0:9443"
	restart.Metrics.Listen = "127.0.0.1:9300"
	want := []string{"listen", "metrics.listen"}
	if got := ServerRestartOnlyChanges(base(t), restart); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart-only fields = %v, want %v", got, want)
	}
}
