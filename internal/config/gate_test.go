package config_test

import (
	"testing"
)

// gateServerBase 是开启门禁的服务端配置骨架：accounts + control 在场（门禁
// 的前置条件），trojan 入站不带静态 users（互斥校验的前提）。服务端只有
// trojan 入站 ⇒ requiredAuth / dns 两条入站规则在此骨架上空转（vacuous）。
const gateServerBase = `
gate:
  enabled: true
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

func TestGateAbsentKeepsBehavior(t *testing.T) {
	// 段缺省 = nil 指针，存量配置（无 gate）行为逐字不变。
	if cfg := mustParse(t, minimalServer, serverProtocols); cfg.Gate != nil {
		t.Fatalf("absent gate must stay nil, got %+v", cfg.Gate)
	}
	if cfg := mustParse(t, minimalClient, clientProtocols); cfg.Gate != nil {
		t.Fatalf("absent gate must stay nil, got %+v", cfg.Gate)
	}
}

func TestGateSectionParses(t *testing.T) {
	cfg := mustParse(t, gateServerBase, serverProtocols)
	if cfg.Gate == nil || !cfg.Gate.Enabled {
		t.Fatalf("gate = %+v, want enabled", cfg.Gate)
	}

	// gate: {} = 段在场但关闭（零值，deny-by-default 不生效）。
	cfg = mustParse(t, `
gate: {}
accounts:
  file: var/accounts.json
control:
  listen: "127.0.0.1:9300"
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params: { cert-file: server.crt, key-file: server.key }
`, serverProtocols)
	if cfg.Gate == nil || cfg.Gate.Enabled {
		t.Fatalf("gate = %+v, want present but disabled", cfg.Gate)
	}
}

func TestGateEnabledRequiresAccounts(t *testing.T) {
	// 门禁视图构建在账户库之上：gate.enabled 而无 accounts = fail-closed 拒绝
	// 启动（静态凭据没有订阅维度可判，不允许静默降级为门禁关闭）。
	mustFail(t, `
gate: { enabled: true }
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params: { cert-file: server.crt, key-file: server.key }
`, serverProtocols, "gate.enabled: requires the accounts section")

	// accounts 在场即通过（服务端骨架，入站规则空转）。
	mustParse(t, gateServerBase, serverProtocols)
}

func TestGateEnabledRequiresAuthOnLoopbackInbounds(t *testing.T) {
	// 门禁开启 ⇒ http/socks5 入站必须配 auth，环回也不例外（收紧
	// requiredAuth：非环回强制之外新增的门禁强制）。
	for _, inboundType := range []string{"http", "socks5"} {
		mustFail(t, `
gate:
  enabled: true
accounts:
  file: var/entitlements.json
inbounds:
  - type: `+inboundType+`
    listen: "127.0.0.1:8080"
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols, "the subscription gate requires auth on every http/socks5 inbound (loopback is not exempt)")
	}

	// 对照：门禁关闭时同一环回 http 入站无需 auth（现状行为不变）。
	mustParse(t, `
inbounds:
  - type: http
    listen: "127.0.0.1:8080"
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols)
}

func TestGateEnabledForbidsDNSInbound(t *testing.T) {
	// 门禁开启 ⇒ dns 入站被禁止（网关无身份概念，fail-closed 一般化规则的实例）。
	mustFail(t, `
gate:
  enabled: true
accounts:
  file: var/entitlements.json
inbounds:
  - type: dns
    listen: "127.0.0.1:53"
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols, "dns inbound is forbidden while the subscription gate is enabled")

	// 对照：门禁关闭时 dns 入站仍合法（现状行为不变）。
	mustParse(t, `
inbounds:
  - type: dns
    listen: "127.0.0.1:53"
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols)
}
