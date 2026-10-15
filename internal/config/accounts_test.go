package config_test

import (
	"testing"
)

// accountsServerBase 是 accounts 模式的服务端配置骨架：trojan 入站不带静态
// users（互斥校验的前提）。
const accountsServerBase = `
accounts:
  file: var/accounts.json
control:
  listen: "127.0.0.1:9300"
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params:
      cert-file: server.crt
      key-file: server.key
`

func TestAccountsModeParses(t *testing.T) {
	cfg := mustParse(t, accountsServerBase, serverProtocols)
	if cfg.Accounts == nil || cfg.Accounts.File != "var/accounts.json" {
		t.Fatalf("accounts = %+v", cfg.Accounts)
	}
	if cfg.Control == nil || cfg.Control.Listen != "127.0.0.1:9300" {
		t.Fatalf("control = %+v", cfg.Control)
	}
}

func TestAccountsControlAbsentKeepsBehavior(t *testing.T) {
	cfg := mustParse(t, minimalServer, serverProtocols)
	if cfg.Accounts != nil || cfg.Control != nil {
		t.Fatalf("absent sections must stay nil: %+v %+v", cfg.Accounts, cfg.Control)
	}
}

func TestAccountsFileRequiredNoImplicitPath(t *testing.T) {
	mustFail(t, `
accounts: {}
control:
  listen: "127.0.0.1:9300"
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params: { cert-file: server.crt, key-file: server.key }
`, serverProtocols, "accounts.file: must not be empty")
}

func TestControlListenRequiredWithAccounts(t *testing.T) {
	mustFail(t, `
accounts:
  file: var/accounts.json
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params: { cert-file: server.crt, key-file: server.key }
`, serverProtocols, "control.listen: required when accounts is configured")
}

func TestControlListenRequiredWhenSectionPresent(t *testing.T) {
	mustFail(t, `
control: {}
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params: { cert-file: server.crt, key-file: server.key }
`, serverProtocols, "control.listen: must not be empty when the control section is present")
}

func TestControlListenLoopbackOnly(t *testing.T) {
	// accounts 模式下。
	mustFail(t, `
accounts:
  file: var/accounts.json
control:
  listen: "0.0.0.0:9300"
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params: { cert-file: server.crt, key-file: server.key }
`, serverProtocols, "only loopback addresses are allowed")

	// 无 accounts（先占位监听）时同样仅环回。
	mustFail(t, `
control:
  listen: "192.168.1.10:9300"
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params: { cert-file: server.crt, key-file: server.key, users: [{ username: alice, password: change-me }] }
`, serverProtocols, "only loopback addresses are allowed")
}

func TestControlListenRegisteredInConflictSet(t *testing.T) {
	mustFail(t, `
api:
  listen: "127.0.0.1:9200"
control:
  listen: "127.0.0.1:9200"
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params: { cert-file: server.crt, key-file: server.key, users: [{ username: alice, password: change-me }] }
`, serverProtocols, "listen port 9200 conflicts")
}

func TestAccountsModeMutexWithStaticUsers(t *testing.T) {
	// params.users（trojan 静态凭据）。
	mustFail(t, `
accounts:
  file: var/accounts.json
control:
  listen: "127.0.0.1:9300"
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params:
      cert-file: server.crt
      key-file: server.key
      users: [{ username: alice, password: change-me }]
`, serverProtocols, "params.users is mutually exclusive with accounts mode")

	// auth.users（http/socks5 共性认证）。
	mustFail(t, `
accounts:
  file: var/accounts.json
control:
  listen: "127.0.0.1:9300"
inbounds:
  - type: http
    listen: "127.0.0.1:8080"
    auth: { users: [{ username: alice, password: change-me }] }
`, clientProtocols, "auth.users is mutually exclusive with accounts mode")
}

func TestControlWithoutAccountsLegal(t *testing.T) {
	// 反向不要求：control 可先于 accounts 占位（静态凭据不受影响）。
	cfg := mustParse(t, `
control:
  listen: "127.0.0.1:9300"
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params:
      cert-file: server.crt
      key-file: server.key
      users: [{ username: alice, password: change-me }]
`, serverProtocols)
	if cfg.Control == nil || cfg.Control.Listen != "127.0.0.1:9300" {
		t.Fatalf("control = %+v", cfg.Control)
	}
}

func TestAccountsControlNormalization(t *testing.T) {
	// 规范化仅去空白，不派生隐式路径/监听。
	cfg := mustParse(t, `
accounts:
  file: "  var/accounts.json  "
control:
  listen: "  127.0.0.1:9300  "
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params: { cert-file: server.crt, key-file: server.key }
`, serverProtocols)
	if cfg.Accounts.File != "var/accounts.json" || cfg.Control.Listen != "127.0.0.1:9300" {
		t.Fatalf("normalization failed: %+v %+v", cfg.Accounts, cfg.Control)
	}
}

func TestAccountsSectionStrictNoGateKnob(t *testing.T) {
	// 本期无 gate 配置段：accounts 段未知字段即解析失败（严格 YAML）。
	mustFail(t, `
accounts:
  file: var/accounts.json
  gate: { enabled: true }
control:
  listen: "127.0.0.1:9300"
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params: { cert-file: server.crt, key-file: server.key }
`, serverProtocols, "field gate not found")
}
