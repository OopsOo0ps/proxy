// 分流判定组合表（组装根对 §5.3 组合树的分派输入）：
// 私网直连是前置硬规则（规则不可覆盖），其后按声明顺序匹配内联规则与
// 各规则源 Provider 的规则表，最后落到缺省动作。
package clientapp

import (
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/routing"
	"github.com/OopsOo0ps/proxy/internal/ruleset"
)

// routeTable 是组装根的分流判定（dialer.Router 与 dnsgw.RouteDecider 的
// 实现）：单一判定入口保证 “DNS 走哪条路 = 流量走哪条路”。
type routeTable struct {
	// privateDirect 为 true 时环回 / 私网 / 链路本地目标一律直连。
	privateDirect bool
	// static 是内联规则引擎（可为 nil：仅规则源或仅缺省动作）。
	static *routing.Engine
	// providers 是规则源列表（当前至多一个；按声明顺序匹配）。
	providers []*ruleset.Provider
	// def 是缺省动作：规则源文档 default > 内联 default > proxy。
	def core.RouteAction
}

// Decide 返回 host 的分流动作（含私网硬规则与缺省动作）。
func (t *routeTable) Decide(host string) core.RouteAction {
	if t.privateDirect && routing.IsLocalTarget(host) {
		return core.RouteDirect
	}
	if t.static != nil {
		if action, ok := t.static.MatchRule(host); ok {
			return action
		}
	}
	for _, p := range t.providers {
		if action, ok := p.MatchRule(host); ok {
			return action
		}
	}
	return t.def
}
