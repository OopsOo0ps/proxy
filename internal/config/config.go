// Package config 是 proxy-client 与 proxy-server 的配置解析层（设计文档 §7）。
//
// schema 形状镜像运行时名词：入站与出口节点都是**带判别字段的列表**，
// 协议专属参数与校验归协议所有——config 只认识"信封"（类型、监听、认证、
// 名字、权重），协议 params 块由协议包定义的结构体严格解码（DecodeParams），
// 协议语义校验（口令规则等）在协议构造器里。已知协议集由组装根传入
// （ProtocolSet），未知协议 / 入站类型在解析期即报用户可读错误。
//
// 配置为严格 YAML：未知字段直接导致启动失败，避免拼写错误被静默忽略。
// 数值缺省全部引用 internal/defaults（L0 纯常量，与领域包实现缺省同源）。
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/defaults"
	"github.com/OopsOo0ps/proxy/internal/netutil"
	"github.com/OopsOo0ps/proxy/internal/routing"
	"gopkg.in/yaml.v3"
)

// 判别字段词表（组装根构造 ProtocolSet 与分派 switch 共用同一拼写）。
const (
	// TypeHTTP / TypeSOCKS5 / TypeDNS 是 client 入站类型；观测口径
	//（core.Proto*）与之一致。
	TypeHTTP   = "http"
	TypeSOCKS5 = "socks5"
	TypeDNS    = "dns"
	// TypeTrojan 是服务端隧道入站类型。
	TypeTrojan = "trojan"
	// ProtocolTrojan 是出口协议判别值。
	ProtocolTrojan = "trojan"
)

// Duration 是支持 YAML 时长写法的 time.Duration：
// 支持 Go 时长语法（"10s"、"1m30s"），纯数字按秒解释。
type Duration time.Duration

// UnmarshalYAML 实现 yaml.Unmarshaler。
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	raw := strings.TrimSpace(node.Value)
	if raw == "" {
		return errors.New("duration is empty")
	}
	if v, err := time.ParseDuration(raw); err == nil {
		*d = Duration(v)
		return nil
	}
	if secs, err := strconv.Atoi(raw); err == nil && secs >= 0 {
		*d = Duration(time.Duration(secs) * time.Second)
		return nil
	}
	return fmt.Errorf("invalid duration %q: use Go duration syntax such as 10s", raw)
}

// Std 返回标准库表示。
func (d Duration) Std() time.Duration { return time.Duration(d) }

// User 是一条用户名/密码凭据（入站认证的共性机制）。
type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// AuthConfig 是入站认证配置（可省；省略 = 不校验认证，仅限环回监听）。
type AuthConfig struct {
	Users []User `yaml:"users"`
}

// —— 信封类型（config 只认识这些，不认识协议字段语义）——

// Inbound 是一个入站端点：判别字段 type + 监听 + 共性认证 + 协议自有 params。
type Inbound struct {
	// Type 是入站类型（http | socks5 | dns | trojan）。
	Type string `yaml:"type"`
	// Listen 是监听地址（host:port；端口 0 = 自动分配）。
	Listen string `yaml:"listen"`
	// Auth 是入站认证（可省）；dns 入站不允许配置。
	Auth *AuthConfig `yaml:"auth,omitempty"`
	// Params 是该入站类型自有参数，由对应协议包的 Params 结构体严格解码；
	// 省略 = 全部取协议缺省。
	Params yaml.Node `yaml:"params,omitempty"`
}

// Node 是一个出口节点：名字 + 判别字段 protocol + 协议自有 params。
type Node struct {
	// Name 是节点名（信封校验：非空且唯一；当前用于错误定位与运维展示）。
	Name string `yaml:"name"`
	// Protocol 是出口协议（trojan | <未来协议>）。
	Protocol string `yaml:"protocol"`
	// Weight 是节点权重；当前节点池为等权轮询，weight 仅要求 >= 0
	//（加权轮询到来时无需改动配置模型）。
	Weight int `yaml:"weight,omitempty"`
	// Params 是协议自有参数块；config 不做协议校验。
	Params yaml.Node `yaml:"params,omitempty"`
}

// Outbound 是出站侧配置（client 专属；server 无出站侧）。
type Outbound struct {
	// Nodes 是出口节点列表。
	Nodes []Node `yaml:"nodes"`
	// Pool 是节点池与预热池策略（协议无关）。
	Pool PoolConfig `yaml:"pool,omitempty"`
}

// PoolConfig 是节点池策略：预热、健康检查与故障转移预算。
type PoolConfig struct {
	// Prewarm 是预热池参数；size = 0 表示关闭预热池。
	Prewarm PrewarmConfig `yaml:"prewarm,omitempty"`
	// Health 是主动健康检查参数；interval = 0 表示关闭主动探测（仅保留被动冷却）。
	Health HealthConfig `yaml:"health,omitempty"`
	// FailoverBudget 是出口节点故障转移链的总时间预算。
	FailoverBudget Duration `yaml:"failover-budget,omitempty"`
}

// EffectiveFailoverBudget 返回生效的故障转移预算（缺省 defaults.FailoverBudget）。
func (p PoolConfig) EffectiveFailoverBudget() time.Duration {
	if p.FailoverBudget <= 0 {
		return defaults.FailoverBudget
	}
	return p.FailoverBudget.Std()
}

// PrewarmConfig 是预热池参数。
type PrewarmConfig struct {
	// Size 是每个节点保留的最大空闲连接数；缺省 defaults.PrewarmSize，0 = 关闭。
	Size *int `yaml:"size,omitempty"`
	// TTL 是空闲连接最长保留时间；缺省 defaults.PrewarmTTL。
	// 应小于服务端握手超时（缺省 10s），否则连接可能在池中已被服务端回收。
	TTL Duration `yaml:"ttl,omitempty"`
}

// EffectiveSize 返回生效的每节点空闲连接上限（缺省 2，0 = 关闭）。
func (p PrewarmConfig) EffectiveSize() int {
	if p.Size == nil {
		return defaults.PrewarmSize
	}
	return *p.Size
}

// EffectiveTTL 返回生效的空闲连接保留时长（缺省 defaults.PrewarmTTL）。
func (p PrewarmConfig) EffectiveTTL() time.Duration {
	if p.TTL <= 0 {
		return defaults.PrewarmTTL
	}
	return p.TTL.Std()
}

// HealthConfig 是主动健康检查参数。
// 行为：按 interval 周期对每个节点做 TCP+TLS 握手探测；节点连续探测失败
// failures 次后被摘除（不再参与拨号），摘除后连续探测成功 successes 次
// 自动加回。interval = 0 关闭主动探测，仅保留真实拨号失败的被动冷却切换。
// 探测只验证节点可达性与 TLS 握手，不发送 Trojan 请求、不校验口令。
type HealthConfig struct {
	// Interval 是探测周期；缺省 defaults.HealthInterval，0 = 关闭。
	Interval *Duration `yaml:"interval,omitempty"`
	// Timeout 是单次探测超时；缺省 defaults.HealthTimeout。
	Timeout Duration `yaml:"timeout,omitempty"`
	// Failures 是连续失败 N 次后摘除；缺省 defaults.HealthFailures。
	Failures *int `yaml:"failures,omitempty"`
	// Successes 是摘除后连续成功 M 次加回；缺省 defaults.HealthSuccesses。
	Successes *int `yaml:"successes,omitempty"`
}

// EffectiveInterval 返回生效的探测周期（缺省 10s；0 = 关闭主动探测）。
func (h HealthConfig) EffectiveInterval() time.Duration {
	if h.Interval == nil {
		return defaults.HealthInterval
	}
	return h.Interval.Std()
}

// EffectiveTimeout 返回生效的单次探测超时（缺省 3s）。
func (h HealthConfig) EffectiveTimeout() time.Duration {
	if h.Timeout <= 0 {
		return defaults.HealthTimeout
	}
	return h.Timeout.Std()
}

// EffectiveFailures 返回生效的摘除阈值（缺省 3）。
func (h HealthConfig) EffectiveFailures() int {
	if h.Failures == nil {
		return defaults.HealthFailures
	}
	return *h.Failures
}

// EffectiveSuccesses 返回生效的加回阈值（缺省 2）。
func (h HealthConfig) EffectiveSuccesses() int {
	if h.Successes == nil {
		return defaults.HealthSuccesses
	}
	return *h.Successes
}

// Ruleset 是一条规则源配置（来源可替换：url 远程 / file 本地）。
type Ruleset struct {
	// Name 是规则源名（信封校验：非空；/stats 展示用）。
	Name string `yaml:"name"`
	// Type 是来源类型：url（省缺）| file。
	Type string `yaml:"type,omitempty"`
	// URL 是远程规则地址（type: url 时必填，仅 http/https）。
	URL string `yaml:"url,omitempty"`
	// Path 是本地规则文件路径（type: file 时必填；构建期严格读取）。
	Path string `yaml:"path,omitempty"`
	// Interval 是 url 源的刷新周期；缺省 defaults.RulesetRefreshInterval，
	// 仅对 url 源有效（显式给出时必须 > 0）。
	Interval *Duration `yaml:"interval,omitempty"`
}

// EffectiveInterval 返回 url 源的刷新周期（缺省 30m）。
func (r Ruleset) EffectiveInterval() time.Duration {
	if r.Interval == nil {
		return defaults.RulesetRefreshInterval
	}
	return r.Interval.Std()
}

// DNSRouting 是 DNS 网关的解析策略（网关监听是入站，见 inbounds type: dns）。
type DNSRouting struct {
	// Remote 是经出口节点访问的 DNS 服务器；缺省 defaults.DNSRemote。
	Remote string `yaml:"remote,omitempty"`
	// Local 是直连名字使用的本机解析器；空 = 读取 /etc/resolv.conf。
	Local []string `yaml:"local,omitempty"`
	// Timeout 是单次查询超时；缺省 defaults.DNSTimeout。
	Timeout Duration `yaml:"timeout,omitempty"`
}

// EffectiveRemote 返回生效的远程解析服务器（缺省 1.1.1.1:53）。
func (d DNSRouting) EffectiveRemote() string {
	if strings.TrimSpace(d.Remote) == "" {
		return defaults.DNSRemote
	}
	return d.Remote
}

// EffectiveTimeout 返回生效的单次查询超时（缺省 5s）。
func (d DNSRouting) EffectiveTimeout() time.Duration {
	if d.Timeout <= 0 {
		return defaults.DNSTimeout
	}
	return d.Timeout.Std()
}

// 内联规则的 match 词表（编译语义与 routing 引擎同源：组合出匹配条目后
// 统一交 routing.CheckEntry 校验）。
const (
	MatchDomain       = "domain"        // 精确域名（裸域）
	MatchDomainSuffix = "domain-suffix" // 子域名（不含裸域）
	MatchIP           = "ip"            // 精确 IP 字面量
	MatchCIDR         = "cidr"          // 网段
)

// Rule 是一条内联分流规则：{ match, value, action } 或缺省规则 { default }。
type Rule struct {
	// Match 是匹配方式（domain | domain-suffix | ip | cidr）。
	Match string
	// Value 是匹配值。
	Value string
	// Action 是动作（direct | proxy | reject）。
	Action core.RouteAction
	// Default 非零表示这是缺省规则（{ default: proxy }）。
	Default *core.RouteAction

	// entry 是解析期组合出的 routing 匹配条目（已校验）。
	entry string
}

// RoutingRule 返回 routing 引擎消费的纯结构形态。
// 结构体直接构造（绕过 YAML 解析）时在此惰性组合并校验匹配条目。
func (r Rule) RoutingRule() (routing.Rule, error) {
	entry := r.entry
	if entry == "" {
		if r.Match == "" {
			return routing.Rule{}, errors.New("routing rule: match is required")
		}
		var err error
		if entry, err = composeMatchEntry(r.Match, r.Value); err != nil {
			return routing.Rule{}, fmt.Errorf("routing rule: %w", err)
		}
	}
	return routing.Rule{Action: r.Action, Match: []string{entry}}, nil
}

// composeMatchEntry 把 match 词表 + value 组合为 routing 引擎的匹配条目
// （与引擎编译语义同源，统一经 routing.CheckEntry 校验）。
func composeMatchEntry(match, value string) (string, error) {
	value = strings.TrimSpace(value)
	switch match {
	case MatchDomain:
		if err := routing.CheckEntry(value); err != nil {
			return "", fmt.Errorf("match %q value %q: %w", match, value, err)
		}
		return value, nil
	case MatchDomainSuffix:
		if err := routing.CheckEntry("*." + value); err != nil {
			return "", fmt.Errorf("match %q value %q: %w", match, value, err)
		}
		return "*." + value, nil
	case MatchIP:
		if _, err := netip.ParseAddr(value); err != nil {
			return "", fmt.Errorf("match %q value %q: %w", match, value, err)
		}
		return value, nil
	case MatchCIDR:
		if err := routing.CheckEntry(value); err != nil {
			return "", fmt.Errorf("match %q value %q: %w", match, value, err)
		}
		return value, nil
	default:
		return "", fmt.Errorf("unknown match %q: want domain, domain-suffix, ip or cidr", match)
	}
}

// UnmarshalYAML 解析一条内联规则（缺省规则或匹配规则），对未知字段报错
// （错误带文档行号）；匹配条目在解析期即校验（词表 + routing 同源校验）。
func (r *Rule) UnmarshalYAML(node *yaml.Node) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		if key != "match" && key != "value" && key != "action" && key != "default" {
			return fmt.Errorf("line %d: unknown field %q in routing rule", node.Content[i].Line, key)
		}
	}
	var raw struct {
		Match   *string `yaml:"match"`
		Value   *string `yaml:"value"`
		Action  *string `yaml:"action"`
		Default *string `yaml:"default"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw.Default != nil {
		if raw.Match != nil || raw.Value != nil || raw.Action != nil {
			return fmt.Errorf("line %d: routing rule: \"default\" must not be combined with match/value/action", node.Line)
		}
		action, err := routing.ParseAction(*raw.Default)
		if err != nil {
			return fmt.Errorf("line %d: %w", node.Line, err)
		}
		r.Default = &action
		return nil
	}
	if raw.Match == nil || raw.Value == nil || raw.Action == nil {
		return fmt.Errorf("line %d: routing rule requires match, value and action", node.Line)
	}
	action, err := routing.ParseAction(*raw.Action)
	if err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}
	entry, err := composeMatchEntry(*raw.Match, *raw.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}
	r.Match, r.Value, r.Action, r.entry = *raw.Match, *raw.Value, action, entry
	return nil
}

// Routing 是分流配置：内联规则（静态）+ 规则源（动态）+ DNS 策略。
type Routing struct {
	// PrivateDirect 为 true 时环回 / 私网 / 链路本地目标一律直连（硬规则，
	// 规则不可覆盖）；缺省 true。
	PrivateDirect *bool `yaml:"private-direct,omitempty"`
	// Rules 是内联规则（按书写顺序匹配，先命中者生效；{ default: ... }
	// 条目指定缺省动作）。
	Rules []Rule `yaml:"rules,omitempty"`
	// Rulesets 是规则源列表（来源可替换：url / file）。当前运行时支持
	// 至多一个规则源（列表形状为多源扩展预留，超出即解析期报错）。
	Rulesets []Ruleset `yaml:"rulesets,omitempty"`
	// DNS 是 DNS 网关解析策略（网关本身是 inbounds 中的 type: dns 入站）。
	DNS *DNSRouting `yaml:"dns,omitempty"`
}

// EffectivePrivateDirect 返回生效的私网直连开关（缺省 true）。
func (r *Routing) EffectivePrivateDirect() bool {
	return r == nil || r.PrivateDirect == nil || *r.PrivateDirect
}

// Limits 是进程级过载保护配置。
type Limits struct {
	// MaxConnections 是进程内并发连接上限；缺省 defaults.MaxConnections，
	// 0 = 不限制。proxy-client 统计全部入站连接之和；proxy-server 统计隧道连接。
	MaxConnections *int `yaml:"max-connections,omitempty"`
}

// EffectiveMaxConnections 返回生效的并发连接上限（缺省 1024，0 = 不限制）。
func (l Limits) EffectiveMaxConnections() int {
	if l.MaxConnections == nil {
		return defaults.MaxConnections
	}
	return *l.MaxConnections
}

// Timeouts 是各类超时。
type Timeouts struct {
	// Dial 是建立目标 / 节点连接的超时。
	Dial Duration `yaml:"dial,omitempty"`
	// Handshake 是握手阶段（TLS + 协议协商）超时。
	Handshake Duration `yaml:"handshake,omitempty"`
	// Idle 是连接空闲回收期限。
	Idle Duration `yaml:"idle,omitempty"`
	// Shutdown 是优雅关停的排空期限：收到 SIGTERM 后先停止接受新连接，
	// 允许存量请求在此期间自然结束，超时后强制断开剩余连接并退出。
	Shutdown Duration `yaml:"shutdown,omitempty"`
}

// EffectiveDial 返回生效的拨号超时（缺省 defaults.DialTimeout）。
func (t Timeouts) EffectiveDial() time.Duration {
	if t.Dial <= 0 {
		return defaults.DialTimeout
	}
	return t.Dial.Std()
}

// EffectiveHandshake 返回生效的握手超时（缺省 defaults.HandshakeTimeout）。
func (t Timeouts) EffectiveHandshake() time.Duration {
	if t.Handshake <= 0 {
		return defaults.HandshakeTimeout
	}
	return t.Handshake.Std()
}

// EffectiveIdle 返回生效的空闲回收期限（缺省 defaults.IdleTimeout）。
func (t Timeouts) EffectiveIdle() time.Duration {
	if t.Idle <= 0 {
		return defaults.IdleTimeout
	}
	return t.Idle.Std()
}

// EffectiveShutdown 返回生效的关停排空期限（缺省 defaults.DrainTimeout）。
func (t Timeouts) EffectiveShutdown() time.Duration {
	if t.Shutdown <= 0 {
		return defaults.DrainTimeout
	}
	return t.Shutdown.Std()
}

// Log 是日志配置。
type Log struct {
	// Level 是日志级别（debug | info | warn | error）；缺省 info。
	Level string `yaml:"level,omitempty"`
	// Format 是日志格式（json | text）；缺省 json。
	Format string `yaml:"format,omitempty"`
}

// API 是运维端点（/metrics /health /stats /log/level）的监听配置。
type API struct {
	// Listen 是监听地址（host:port），空 = 不启用。
	Listen string `yaml:"listen,omitempty"`
	// AllowRemote 显式允许把运维端点绑定到非环回地址（默认拒绝——一次绑定
	// 疏忽不应把拓扑与运行时状态暴露到网络）。只影响只读端点；/log/level 的
	// 状态变更永远只接受环回来源。
	AllowRemote bool `yaml:"allow-remote,omitempty"`
}

// Config 是 proxy-client 与 proxy-server 共用的配置信封：客户端 schema 与
// 服务端 schema 镜像同一模式（判别字段列表 + 协议自有 params），差异只在
// 组装根传入的 ProtocolSet（client = {http, socks5, dns} 入站 + trojan 出站；
// server = {trojan} 入站、无出站）。
type Config struct {
	Log Log `yaml:"log,omitempty"`
	// API 是运维端点配置。
	API API `yaml:"api,omitempty"`
	// Inbounds 是入站端点列表（判别字段 type）。
	Inbounds []Inbound `yaml:"inbounds"`
	// Outbound 是出站侧（client 专属；server schema 无此段）。
	Outbound *Outbound `yaml:"outbound,omitempty"`
	// Routing 是分流配置（client 专属）。
	Routing *Routing `yaml:"routing,omitempty"`
	// Limits 是进程级过载保护。
	Limits Limits `yaml:"limits,omitempty"`
	// Timeouts 是各类超时。
	Timeouts Timeouts `yaml:"timeouts,omitempty"`
}

// ProtocolSet 是组装根能分派的协议全集（解析期校验依据，设计文档 §7.3）：
// Inbounds 列出允许的入站 type；Outbound 列出允许的出口节点 protocol
// （空 = 该组装根没有出站侧，配置中出现 outbound/routing 段即报错）。
type ProtocolSet struct {
	Inbounds []string
	Outbound []string
}

func (s ProtocolSet) allowsInbound(t string) bool {
	for _, v := range s.Inbounds {
		if v == t {
			return true
		}
	}
	return false
}

func (s ProtocolSet) allowsOutbound(p string) bool {
	for _, v := range s.Outbound {
		if v == p {
			return true
		}
	}
	return false
}

// Load 从 path 读取、解析并校验配置（protocols 为组装根的已知协议集）。
func Load(path string, protocols ProtocolSet) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(data, protocols)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &cfg, nil
}

// Parse 解析配置 YAML 并校验（严格模式：未知字段报错）。
// 数值缺省全部引用 internal/defaults；信封校验在此完成，协议语义校验
// 由协议构造器负责（config 不认识协议字段语义）。
func Parse(data []byte, protocols ProtocolSet) (Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, errors.New("config is empty")
		}
		return Config{}, fmt.Errorf("parse yaml: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(protocols); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// DecodeParams 把 params 块严格解码进协议包定义的参数结构体
// （KnownFields(true)；协议 Params 结构体只有 struct tag，协议包零 yaml 依赖）。
// 节点为零值（字段缺省）或显式 null 时不做任何事（保持 into 的零值）。
func DecodeParams(n yaml.Node, into any) error {
	switch {
	case n.Kind == 0:
		return nil
	case n.Kind == yaml.ScalarNode && n.Tag == "!!null":
		return nil
	case n.Kind != yaml.MappingNode:
		return fmt.Errorf("params: expected a mapping, got %s", n.ShortTag())
	}
	// yaml.Node 无法直接按 KnownFields 严格解码：先把节点规范化回 YAML
	// 文本，再以严格解码器读入（错误保留字段路径）。
	data, err := yaml.Marshal(&n)
	if err != nil {
		return fmt.Errorf("params: encode: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("params: %w", err)
	}
	return nil
}

func (c *Config) applyDefaults() {
	if strings.TrimSpace(c.Log.Level) == "" {
		c.Log.Level = defaults.LogLevel
	}
	if strings.TrimSpace(c.Log.Format) == "" {
		c.Log.Format = defaults.LogFormat
	}
}

func (c *Config) validate(ps ProtocolSet) error {
	if err := validateLog(c.Log); err != nil {
		return err
	}
	if err := validateAPI(c.API); err != nil {
		return err
	}
	if len(c.Inbounds) == 0 {
		return errors.New("inbounds: at least one inbound must be configured")
	}

	// 信封：入站 type ∈ ProtocolSet、listen 可解析、端口不冲突、auth 通用检查。
	conflicts := newListenConflictSet()
	for i := range c.Inbounds {
		ic := &c.Inbounds[i]
		what := fmt.Sprintf("inbounds[%d]", i)
		if !ps.allowsInbound(ic.Type) {
			return fmt.Errorf("%s: unknown inbound type %q", what, ic.Type)
		}
		if ic.Listen == "" {
			return fmt.Errorf("%s: listen must not be empty", what)
		}
		if err := conflicts.add(what, ic.Listen); err != nil {
			return err
		}
		if ic.Type == TypeDNS {
			if ic.Auth != nil {
				return fmt.Errorf("%s: dns inbound does not support auth", what)
			}
			if !IsLoopbackListen(ic.Listen) {
				return fmt.Errorf("%s: only loopback addresses are allowed for the dns gateway (got %q): refusing to run as an open resolver", what, ic.Listen)
			}
		}
		if err := validateAuth(what+".auth", ic.Auth, requiredAuth(ic.Type, ic.Listen)); err != nil {
			return err
		}
	}
	if err := conflicts.check(); err != nil {
		return err
	}
	if c.API.Listen != "" {
		if err := conflicts.add("api.listen", c.API.Listen); err != nil {
			return err
		}
		if err := conflicts.check(); err != nil {
			return err
		}
	}

	// 出站与分流仅允许有出站侧的组装根（server = trojan 入站 + 直连出站特化）。
	if c.Outbound != nil && len(ps.Outbound) == 0 {
		return errors.New("outbound: this binary has no outbound side")
	}
	if c.Routing != nil && len(ps.Outbound) == 0 {
		return errors.New("routing: this binary has no routing side")
	}
	if c.Outbound != nil {
		if err := validateNodes(c.Outbound, ps); err != nil {
			return err
		}
	}
	// 组合校验：出站节点数为零时，routing 不得产生 proxy 判定
	//（缺省动作 proxy 与内联规则都在校验范围内；server 无出站侧不适用）。
	if len(ps.Outbound) > 0 && c.needsExitNodes() && c.nodeCount() == 0 {
		return errors.New("routing: at least one exit node is required when rules or the default action route to proxy")
	}
	if c.Routing != nil {
		if err := c.Routing.validate(c.dnsGatewayListen()); err != nil {
			return err
		}
	}

	if c.Limits.EffectiveMaxConnections() < 0 {
		return errors.New("limits.max-connections: must not be negative (0 disables the limit)")
	}
	if err := validateTimeouts(c.Timeouts); err != nil {
		return err
	}
	return nil
}

// needsExitNodes 报告 routing 是否会产生 proxy 判定（缺省动作或任一规则）。
// 未配置 routing 段时缺省动作仍为 proxy（与组装根的缺省同源）。
func (c *Config) needsExitNodes() bool {
	if c.Routing == nil {
		return true
	}
	for i := range c.Routing.Rules {
		if c.Routing.Rules[i].Default == nil && c.Routing.Rules[i].Action == core.RouteProxy {
			return true
		}
	}
	return c.routingDefault() == core.RouteProxy
}

// routingDefault 返回内联规则指定的缺省动作（未指定时 proxy；
// 规则源文档的 default 在组装根合成时优先，见 clientapp）。
func (c *Config) routingDefault() core.RouteAction {
	if c.Routing != nil {
		for i := range c.Routing.Rules {
			if d := c.Routing.Rules[i].Default; d != nil {
				return *d
			}
		}
	}
	return core.RouteProxy
}

func (c *Config) nodeCount() int {
	if c.Outbound == nil {
		return 0
	}
	return len(c.Outbound.Nodes)
}

func (c *Config) dnsGatewayListen() string {
	for i := range c.Inbounds {
		if c.Inbounds[i].Type == TypeDNS {
			return c.Inbounds[i].Listen
		}
	}
	return ""
}

func validateNodes(ob *Outbound, ps ProtocolSet) error {
	seen := make(map[string]bool, len(ob.Nodes))
	for i := range ob.Nodes {
		n := &ob.Nodes[i]
		what := fmt.Sprintf("outbound.nodes[%d]", i)
		if strings.TrimSpace(n.Name) == "" {
			return fmt.Errorf("%s: name must not be empty", what)
		}
		if seen[n.Name] {
			return fmt.Errorf("%s: duplicate node name %q", what, n.Name)
		}
		seen[n.Name] = true
		if !ps.allowsOutbound(n.Protocol) {
			return fmt.Errorf("%s (%s): unknown protocol %q", what, n.Name, n.Protocol)
		}
		if n.Weight < 0 {
			return fmt.Errorf("%s (%s): weight must not be negative", what, n.Name)
		}
	}
	return validatePool(ob.Pool)
}

func validatePool(p PoolConfig) error {
	if p.Prewarm.EffectiveSize() < 0 {
		return errors.New("outbound.pool.prewarm.size: must not be negative (0 disables the pool)")
	}
	if p.Prewarm.TTL < 0 {
		return errors.New("outbound.pool.prewarm.ttl: must not be negative")
	}
	if p.Health.Interval != nil && p.Health.Interval.Std() < 0 {
		return errors.New("outbound.pool.health.interval: must not be negative (0 disables active probing)")
	}
	if p.Health.Timeout < 0 {
		return errors.New("outbound.pool.health.timeout: must not be negative")
	}
	if p.Health.Failures != nil && *p.Health.Failures < 1 {
		return errors.New("outbound.pool.health.failures: must be >= 1")
	}
	if p.Health.Successes != nil && *p.Health.Successes < 1 {
		return errors.New("outbound.pool.health.successes: must be >= 1")
	}
	if p.FailoverBudget < 0 {
		return errors.New("outbound.pool.failover-budget: must not be negative")
	}
	return nil
}

func (r *Routing) validate(dnsListen string) error {
	if len(r.Rulesets) > 1 {
		return errors.New("routing.rulesets: at most one rule source is supported")
	}
	for i := range r.Rulesets {
		if err := r.Rulesets[i].validate(); err != nil {
			return fmt.Errorf("routing.rulesets[%d]: %w", i, err)
		}
	}
	if r.DNS != nil {
		if err := r.DNS.validate(dnsListen); err != nil {
			return err
		}
	}
	return nil
}

func (r Ruleset) validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("name must not be empty")
	}
	switch r.Type {
	case "", "url":
		if r.Path != "" {
			return errors.New("url source: path is not allowed (use url)")
		}
		if err := validateRulesURL(r.URL); err != nil {
			return fmt.Errorf("url source: %w", err)
		}
		if r.Interval != nil && r.Interval.Std() <= 0 {
			return errors.New("interval: must be positive (the default refresh interval applies when omitted)")
		}
	case "file":
		if r.URL != "" {
			return errors.New("file source: url is not allowed (use path)")
		}
		if strings.TrimSpace(r.Path) == "" {
			return errors.New("file source: path must not be empty")
		}
		if r.Interval != nil {
			return errors.New("interval only applies to url sources")
		}
	default:
		return fmt.Errorf("unknown type %q: want url or file", r.Type)
	}
	return nil
}

func (d DNSRouting) validate(dnsListen string) error {
	if err := validateHostPort("routing.dns.remote", d.EffectiveRemote()); err != nil {
		return err
	}
	for i, addr := range d.Local {
		what := fmt.Sprintf("routing.dns.local[%d]", i)
		if err := validateHostPort(what, addr); err != nil {
			return err
		}
		if dnsListen != "" && netutil.SameHostPort(addr, dnsListen) {
			return fmt.Errorf("%s: %q points to the DNS gateway itself", what, addr)
		}
	}
	if d.Timeout < 0 {
		return errors.New("routing.dns.timeout: must not be negative")
	}
	return nil
}

// validateAuth 校验入站认证（auth 是入站共性机制，通用检查归 config）。
func validateAuth(what string, a *AuthConfig, required bool) error {
	if a == nil || len(a.Users) == 0 {
		if required {
			return fmt.Errorf("%s: listening on a non-loopback address requires auth", what)
		}
		return nil
	}
	seen := make(map[string]bool, len(a.Users))
	for i, u := range a.Users {
		if strings.TrimSpace(u.Username) == "" {
			return fmt.Errorf("%s.users[%d]: username must not be empty", what, i)
		}
		if u.Password == "" {
			return fmt.Errorf("%s.users[%d] (%s): password must not be empty", what, i, u.Username)
		}
		if strings.ContainsAny(u.Username+u.Password, "\r\n") {
			return fmt.Errorf("%s.users[%d] (%s): username/password must not contain CR or LF", what, i, u.Username)
		}
		if seen[u.Username] {
			return fmt.Errorf("%s: duplicate username %q", what, u.Username)
		}
		seen[u.Username] = true
	}
	return nil
}

// requiredAuth 报告某入站在该监听地址上是否必须配置共性认证。
// dns 网关无认证概念；trojan 服务端的凭据属协议 params（协议自有校验）；
// http/socks5 监听非环回地址时必填。
func requiredAuth(inboundType, listen string) bool {
	if inboundType == TypeDNS || inboundType == TypeTrojan {
		return false
	}
	return !IsLoopbackListen(listen)
}

func validateLog(l Log) error {
	switch strings.ToLower(strings.TrimSpace(l.Level)) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level: invalid value %q: want debug, info, warn or error", l.Level)
	}
	switch strings.ToLower(strings.TrimSpace(l.Format)) {
	case "json", "text":
	default:
		return fmt.Errorf("log.format: invalid value %q: want json or text", l.Format)
	}
	return nil
}

func validateAPI(a API) error {
	if a.Listen == "" {
		if a.AllowRemote {
			return errors.New("api.allow-remote is set but api.listen is empty (the flag only applies to a bound listener)")
		}
		return nil
	}
	if err := validateListenAddr("api.listen", a.Listen); err != nil {
		return err
	}
	if !IsLoopbackListen(a.Listen) && !a.AllowRemote {
		return fmt.Errorf("api.listen: binding to non-loopback address %q requires api.allow-remote: true (ops endpoints expose topology and runtime state)", a.Listen)
	}
	return nil
}

func validateTimeouts(t Timeouts) error {
	for _, kv := range []struct {
		name string
		d    Duration
	}{
		{"timeouts.dial", t.Dial},
		{"timeouts.handshake", t.Handshake},
		{"timeouts.idle", t.Idle},
		{"timeouts.shutdown", t.Shutdown},
	} {
		if kv.d < 0 {
			return fmt.Errorf("%s: must not be negative", kv.name)
		}
	}
	return nil
}

// listenConflictSet 收集全部监听地址并检测端口冲突：
// 相同端口且（主机相同或一方为通配地址）即冲突；端口 0（自动分配）不参与。
type listenConflictSet struct {
	entries []conflictEntry
}

type conflictEntry struct {
	what string
	host string
	port string
}

func newListenConflictSet() *listenConflictSet { return &listenConflictSet{} }

func (s *listenConflictSet) add(what, addr string) error {
	if err := validateListenAddr(what, addr); err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(addr)
	s.entries = append(s.entries, conflictEntry{what: what, host: host, port: port})
	return nil
}

func (s *listenConflictSet) check() error {
	for i := range s.entries {
		for j := i + 1; j < len(s.entries); j++ {
			a, b := s.entries[i], s.entries[j]
			if a.port == "0" || b.port == "0" || a.port != b.port {
				continue
			}
			if a.host == b.host || isWildcardHost(a.host) || isWildcardHost(b.host) {
				return fmt.Errorf("%s and %s: listen port %s conflicts (same port on the same or a wildcard host)", a.what, b.what, a.port)
			}
		}
	}
	return nil
}

func isWildcardHost(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::"
}

// validateRulesURL 校验远程规则 URL：仅允许 http/https 且必须有主机。
func validateRulesURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q: want http or https", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("missing host in %q", raw)
	}
	return nil
}

// validateListenAddr 校验 host:port 形式的监听地址（允许空 host 与端口 0）。
func validateListenAddr(what, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s: invalid listen address %q: %w", what, addr, err)
	}
	if err := validatePort(port); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if host != "" && host != "localhost" {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("%s: invalid host %q in %q", what, host, addr)
		}
	}
	return nil
}

// validateHostPort 校验必须带端口的连接地址（端口 1-65535）。
func validateHostPort(what, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s: invalid address %q: %w", what, addr, err)
	}
	if host == "" {
		return fmt.Errorf("%s: host must not be empty in %q", what, addr)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("%s: invalid port %q in %q", what, port, addr)
	}
	return nil
}

func validatePort(port string) error {
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

// IsLoopbackListen 判断监听地址是否仅绑定本机环回接口。
// 无法确认（空 host、主机名）时按非环回处理，从严要求认证。
func IsLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback()
}
