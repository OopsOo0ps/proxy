package config_test

import (
	"testing"
)

// 客户端 entitlement（迭代④，设计书 §3.1 客户端行）：客户端 schema 复用
// accounts 段承载管理员分发的 entitlement 文件（同一文件格式 = 文件分发零
// 转换），与入站静态凭据复合（静态 ∧ 订阅）；服务端专属规则（accounts 模式
// 互斥静态凭据、control.listen 必填）按 ProtocolSet 分派，不再错误地约束
// 客户端。

// clientEntitlementBase 是开启客户端门禁的配置骨架：gate + accounts（复合
// 认证的前置条件），http/socks5 入站带静态 users（复合体的第一维）。
const clientEntitlementBase = `
gate:
  enabled: true
accounts:
  file: var/entitlements.json
inbounds:
  - type: http
    listen: "127.0.0.1:8080"
    auth: { users: [{ username: alice, password: change-me }] }
  - type: socks5
    listen: "127.0.0.1:1080"
    auth: { users: [{ username: alice, password: change-me }] }
outbound: { nodes: [{ name: a, protocol: trojan }] }
`

func TestClientEntitlementStaticUsersWithEntitlementLegal(t *testing.T) {
	// 客户端允许静态 users + entitlement 共存（复合认证），且无需 control。
	cfg := mustParse(t, clientEntitlementBase, clientProtocols)
	if cfg.Gate == nil || !cfg.Gate.Enabled {
		t.Fatalf("gate = %+v, want enabled", cfg.Gate)
	}
	if cfg.Accounts == nil || cfg.Accounts.File != "var/entitlements.json" {
		t.Fatalf("accounts = %+v", cfg.Accounts)
	}
	if cfg.Control != nil {
		t.Fatalf("control = %+v, want nil (client has no control plane)", cfg.Control)
	}
}

func TestClientControlSectionForbidden(t *testing.T) {
	// 客户端无控制面（设计书 §2.2：clientapp 不获得 →control 边）；
	// control 段出现即解析失败，不允许「配了但不生效」的静默忽略。
	mustFail(t, clientEntitlementBase+`
control:
  listen: "127.0.0.1:9300"
`, clientProtocols, "control: this binary has no control plane")

	// 无 accounts 时同样拒绝（客户端词汇表里没有 control）。
	mustFail(t, `
control:
  listen: "127.0.0.1:9300"
inbounds:
  - type: http
    listen: "127.0.0.1:8080"
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols, "control: this binary has no control plane")
}

func TestClientAccountsRequiresGateEnabled(t *testing.T) {
	// 客户端上 accounts 文件只服务门禁：孤立配置按解析期错误拒绝
	//（不允许「配置了 entitlement 但门禁关闭」的静默漂移）。
	mustFail(t, `
accounts:
  file: var/entitlements.json
inbounds:
  - type: http
    listen: "127.0.0.1:8080"
    auth: { users: [{ username: alice, password: change-me }] }
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols, "accounts: on the client the accounts file is the entitlement source of the subscription gate; set gate.enabled or remove the accounts section")

	// gate 段在场但 enabled: false 同样拒绝（与段缺省同语义）。
	mustFail(t, `
gate: {}
accounts:
  file: var/entitlements.json
inbounds:
  - type: http
    listen: "127.0.0.1:8080"
    auth: { users: [{ username: alice, password: change-me }] }
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols, "set gate.enabled or remove the accounts section")
}

func TestClientGateEnabledRequiresEntitlementFile(t *testing.T) {
	// 客户端与服务端同一条解析期 fail-closed 规则：gate.enabled ⇒ accounts
	// 段在场（客户端的判定依据 = entitlement 文件）。
	mustFail(t, `
gate: { enabled: true }
inbounds:
  - type: http
    listen: "127.0.0.1:8080"
    auth: { users: [{ username: alice, password: change-me }] }
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols, "gate.enabled: requires the accounts section")
}

func TestClientEntitlementFileRequiredNoImplicitPath(t *testing.T) {
	mustFail(t, `
gate: { enabled: true }
accounts: {}
inbounds:
  - type: http
    listen: "127.0.0.1:8080"
    auth: { users: [{ username: alice, password: change-me }] }
outbound: { nodes: [{ name: a, protocol: trojan }] }
`, clientProtocols, "accounts.file: must not be empty")
}
