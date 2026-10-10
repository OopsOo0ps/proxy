package config

import (
	"os"
	"path/filepath"
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
