// Package routing 实现基于规则的目标分流：直连（direct）或走代理（proxy）。
//
// 规则按书写顺序匹配，先命中者生效；未命中时使用默认动作。
// 支持的通配条目：
//   - 精确域名："example.com"（仅匹配裸域名本身）
//   - 通配域名："*.example.com"（匹配其子域名，不含裸域）
//   - 精确 IP："1.2.3.4"、"2001:db8::1"
//   - 网段："10.0.0.0/8"、"fc00::/7"
package routing

import (
	"fmt"
	"net/netip"
	"strings"

	"gopkg.in/yaml.v3"
)

// Action 是分流决策结果。
type Action uint8

const (
	// Direct 表示目标直连。
	Direct Action = iota
	// Proxy 表示目标经出口节点转发。
	Proxy
)

// String 返回动作的配置写法。
func (a Action) String() string {
	switch a {
	case Direct:
		return "direct"
	case Proxy:
		return "proxy"
	default:
		return "unknown"
	}
}

// ParseAction 解析配置中的动作字符串（direct / proxy，大小写不敏感）。
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "direct":
		return Direct, nil
	case "proxy":
		return Proxy, nil
	default:
		return 0, fmt.Errorf("invalid routing action %q: want direct or proxy", s)
	}
}

// UnmarshalYAML 支持规则文件中的 "default: direct|proxy" 写法。
func (a *Action) UnmarshalYAML(node *yaml.Node) error {
	action, err := ParseAction(node.Value)
	if err != nil {
		return err
	}
	*a = action
	return nil
}

// Options 控制引擎行为。
type Options struct {
	// Default 是未命中任何规则时的默认动作。
	Default Action
	// PrivateDirect 为 true 时，环回 / 私网 / 链路本地 / 组播 / 未指定地址
	// 以及 localhost 一律直连，避免把内网流量误发到远端节点。
	PrivateDirect bool
}

// Engine 是基于编译后规则的只读分流引擎，可安全并发使用。
type Engine struct {
	rules         []compiledRule
	def           Action
	privateDirect bool
}

type compiledRule struct {
	action   Action
	matchers []matcher
}

// NewEngine 编译规则构建引擎；rules 可以为 nil（仅用内置行为与默认动作）。
// 规则文件中的 default（若存在）优先于 opts.Default。
func NewEngine(rules *Rules, opts Options) (*Engine, error) {
	e := &Engine{def: opts.Default, privateDirect: opts.PrivateDirect}
	if rules == nil {
		return e, nil
	}
	if rules.Default != nil {
		e.def = *rules.Default
	}
	for i, r := range rules.Rules {
		cr := compiledRule{action: r.Action}
		for _, entry := range r.Match {
			m, err := compileMatcher(entry)
			if err != nil {
				return nil, fmt.Errorf("rule %d: %w", i+1, err)
			}
			cr.matchers = append(cr.matchers, m)
		}
		e.rules = append(e.rules, cr)
	}
	return e, nil
}

// Decide 返回 host（域名或 IP 字面量，不含端口）的分流动作。
func (e *Engine) Decide(host string) Action {
	host = normalizeHost(host)
	if host == "" {
		return e.def
	}
	if e.privateDirect && isLocalTarget(host) {
		return Direct
	}
	for _, rule := range e.rules {
		for _, m := range rule.matchers {
			if m.match(host) {
				return rule.action
			}
		}
	}
	return e.def
}

// normalizeHost 统一小写、去掉首尾空白、IPv6 方括号与 FQDN 末尾的点。
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return strings.ToLower(host)
}

// isLocalTarget 判断主机名或 IP 是否属于本机 / 内网 / 特殊地址段。
func isLocalTarget(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

type matcher interface {
	match(host string) bool
}

// exactMatcher 匹配裸域名或精确 IP。
type exactMatcher struct{ value string }

func (m exactMatcher) match(host string) bool { return host == m.value }

// wildcardMatcher 匹配 "*.suffix"：suffix 已带前导点（如 ".example.com"）。
type wildcardMatcher struct{ suffix string }

func (m wildcardMatcher) match(host string) bool {
	return len(host) > len(m.suffix) && strings.HasSuffix(host, m.suffix)
}

// cidrMatcher 匹配 IP 所属网段。
type cidrMatcher struct{ prefix netip.Prefix }

func (m cidrMatcher) match(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return m.prefix.Contains(ip)
}

func compileMatcher(entry string) (matcher, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil, fmt.Errorf("empty match entry")
	}
	if strings.ContainsAny(entry, " \t") {
		return nil, fmt.Errorf("invalid match entry %q: contains whitespace", entry)
	}

	if suffix, ok := strings.CutPrefix(entry, "*."); ok {
		suffix = strings.ToLower(strings.Trim(suffix, "."))
		if suffix == "" || strings.ContainsAny(suffix, "*/\\") {
			return nil, fmt.Errorf("invalid wildcard pattern %q: want \"*.example.com\"", entry)
		}
		return wildcardMatcher{suffix: "." + suffix}, nil
	}

	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(strings.ToLower(entry))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", entry, err)
		}
		return cidrMatcher{prefix: prefix.Masked()}, nil
	}

	value := strings.ToLower(strings.TrimSuffix(entry, "."))
	if strings.Contains(value, "*") {
		return nil, fmt.Errorf("invalid match entry %q: wildcard must use \"*.suffix\" form", entry)
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return exactMatcher{value: value}, nil
	}
	if err := validateDomain(value); err != nil {
		return nil, err
	}
	return exactMatcher{value: value}, nil
}

// validateDomain 做宽容的域名校验：拒绝空白、控制字符与常见非法符号，
// 允许下划线等真实场景中存在的字符；国际化域名请使用 punycode 写法。
func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("empty domain")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain %q is too long", domain)
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return fmt.Errorf("invalid domain %q: empty label", domain)
		}
		if len(label) > 63 {
			return fmt.Errorf("invalid domain %q: label too long", domain)
		}
	}
	for _, r := range domain {
		if r <= ' ' || strings.ContainsRune("*/\\:@?#[]\"'<>|", r) {
			return fmt.Errorf("invalid domain %q", domain)
		}
	}
	return nil
}
