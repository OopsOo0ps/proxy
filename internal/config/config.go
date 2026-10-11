// Package config 负责 proxy-client 与 proxy-server 的配置解析、默认值与校验。
//
// 配置采用 YAML 严格模式：未知字段会直接报错，避免拼写错误被静默忽略。
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

	"github.com/OopsOo0ps/proxy/internal/netutil"
	"github.com/OopsOo0ps/proxy/internal/shutdown"
	"gopkg.in/yaml.v3"
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

// User 是一条用户名/密码凭据。
type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Node 描述一个出口节点（Trojan over TLS）。
type Node struct {
	Addr     string `yaml:"addr"`     // host:port
	Password string `yaml:"password"` // 隧道口令
	SNI      string `yaml:"sni"`      // 可选：TLS SNI / 证书校验名，缺省取 addr 的主机名
}

// Pool 是上游隧道空闲连接池（预热）配置：请求优先复用已完成握手的空闲连接，
// 减少到出口节点的握手开销；详见 internal/connpool。
type Pool struct {
	// MaxIdle 是每个出口节点保留的最大空闲连接数；缺省 2，0 = 关闭。
	MaxIdle *int `yaml:"max_idle"`
	// IdleTTL 是空闲连接的最长保留时间，缺省 5s；
	// 应小于服务端 timeouts.handshake（缺省 10s），否则连接可能在池中已被服务端回收。
	IdleTTL Duration `yaml:"idle_ttl"`
}

// 连接池缺省值。
const (
	defaultPoolMaxIdle = 2
	defaultPoolIdleTTL = 5 * time.Second
)

// defaultFailoverBudget 是出口节点故障转移链的缺省总时间预算（proxy-client 专用）。
// 与 nodes.DefaultFailoverBudget 保持一致：一个约束配置层默认值，一个约束库调用方。
const defaultFailoverBudget = 30 * time.Second

// EffectiveMaxIdle 返回生效的每节点空闲连接上限（缺省 2，0 = 关闭）。
func (p Pool) EffectiveMaxIdle() int {
	if p.MaxIdle == nil {
		return defaultPoolMaxIdle
	}
	return *p.MaxIdle
}

// EffectiveIdleTTL 返回生效的空闲连接保留时长（缺省 5s）。
func (p Pool) EffectiveIdleTTL() time.Duration {
	if p.IdleTTL <= 0 {
		return defaultPoolIdleTTL
	}
	return p.IdleTTL.Std()
}

// HealthCheck 是出口节点的主动健康检查配置（路线图 3.3）。
//
// 行为：按 interval 周期对每个节点做 TCP+TLS 握手探测；节点连续探测失败
// failures 次后被摘除（不再参与拨号），摘除后连续探测成功 successes 次
// 自动加回。interval = 0 关闭主动探测，仅保留真实拨号失败的被动冷却切换。
//
// 探测只验证节点可达性与 TLS 握手，不发送 Trojan 请求、不校验口令：
// 口令错误等隧道层问题仍由真实流量的被动冷却兜底。
type HealthCheck struct {
	Interval  *Duration `yaml:"interval"`  // 探测周期；缺省 10s，0 = 关闭
	Timeout   Duration  `yaml:"timeout"`   // 单次探测超时；缺省 3s
	Failures  *int      `yaml:"failures"`  // 连续失败 N 次后摘除；缺省 3
	Successes *int      `yaml:"successes"` // 摘除后连续成功 M 次加回；缺省 2
}

// 主动健康检查缺省值。
const (
	defaultHealthInterval  = 10 * time.Second
	defaultHealthTimeout   = 3 * time.Second
	defaultHealthFailures  = 3
	defaultHealthSuccesses = 2
)

// EffectiveInterval 返回生效的探测周期（缺省 10s；0 = 关闭主动探测）。
func (h HealthCheck) EffectiveInterval() time.Duration {
	if h.Interval == nil {
		return defaultHealthInterval
	}
	return h.Interval.Std()
}

// EffectiveTimeout 返回生效的单次探测超时（缺省 3s）。
func (h HealthCheck) EffectiveTimeout() time.Duration {
	if h.Timeout <= 0 {
		return defaultHealthTimeout
	}
	return h.Timeout.Std()
}

// EffectiveFailures 返回生效的摘除阈值（缺省 3）。
func (h HealthCheck) EffectiveFailures() int {
	if h.Failures == nil {
		return defaultHealthFailures
	}
	return *h.Failures
}

// EffectiveSuccesses 返回生效的加回阈值（缺省 2）。
func (h HealthCheck) EffectiveSuccesses() int {
	if h.Successes == nil {
		return defaultHealthSuccesses
	}
	return *h.Successes
}

// Inbound 描述本机入站代理监听。
type Inbound struct {
	HTTP   string `yaml:"http"`   // host:port，空 = 不启用
	SOCKS5 string `yaml:"socks5"` // host:port，空 = 不启用
	Auth   []User `yaml:"auth"`   // 凭据列表；监听非环回地址时必填
}

// Limits 是进程级过载保护配置。
type Limits struct {
	// MaxConnections 是进程内并发连接上限；缺省 1024，0 = 不限制。
	// proxy-client 统计 HTTP + SOCKS5 入站连接之和；proxy-server 统计隧道连接。
	MaxConnections *int `yaml:"max_connections"`
}

// defaultMaxConnections 是连接上限缺省值。
const defaultMaxConnections = 1024

// EffectiveMaxConnections 返回生效的并发连接上限（缺省 1024，0 = 不限制）。
func (l Limits) EffectiveMaxConnections() int {
	if l.MaxConnections == nil {
		return defaultMaxConnections
	}
	return *l.MaxConnections
}

// ClientTLS 是客户端连接出口节点的 TLS 参数。
type ClientTLS struct {
	CAFile             string `yaml:"ca_file"`              // 自定义 CA（自签证书场景）
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"` // 仅测试/自签调试使用
}

// ServerTLS 是服务端隧道证书配置。
type ServerTLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Routing 是分流配置。规则源二选一：本地 rules_file 或远程 rules_url。
type Routing struct {
	Default       string `yaml:"default"`        // direct | proxy，缺省 proxy
	RulesFile     string `yaml:"rules_file"`     // 可选：规则文件路径（与 rules_url 互斥）
	RulesURL      string `yaml:"rules_url"`      // 可选：远程规则 URL（http/https，与 rules_file 互斥）
	PrivateDirect *bool  `yaml:"private_direct"` // 环回/私网目标直连，缺省 true

	// RulesRefreshInterval 是远程规则的刷新周期（路线图 3.4）：缺省 30m，
	// 0 = 仅启动时拉取一次、不周期刷新；仅对 rules_url 有效。
	RulesRefreshInterval *Duration `yaml:"rules_refresh_interval"`
}

// defaultRulesRefreshInterval 是远程规则的缺省刷新周期。
const defaultRulesRefreshInterval = 30 * time.Minute

// EffectiveRulesRefreshInterval 返回远程规则的刷新周期（缺省 30m；0 = 仅启动拉取一次）。
func (r Routing) EffectiveRulesRefreshInterval() time.Duration {
	if r.RulesRefreshInterval == nil {
		return defaultRulesRefreshInterval
	}
	return r.RulesRefreshInterval.Std()
}

// Timeouts 是各类超时。
type Timeouts struct {
	Dial      Duration `yaml:"dial"`      // 建立目标/节点连接
	Handshake Duration `yaml:"handshake"` // 握手阶段（TLS + 协议协商）
	Idle      Duration `yaml:"idle"`      // 连接空闲回收
	// Failover 是单次请求在出口节点故障转移链上的总时间预算：覆盖全部候选
	// 节点的建连、TLS/Trojan 握手与请求写出（proxy-client 专用，缺省 30s）。
	// 请求上下文更短时以更短者为准；直连路径与健康探测不受影响。
	Failover Duration `yaml:"failover"`
	// Shutdown 是优雅关停的排空期限：收到 SIGTERM 后先停止接受新连接，
	// 允许存量请求在此期间自然结束，超时后强制断开剩余连接并退出。
	Shutdown Duration `yaml:"shutdown"`
}

// Metrics 是运维端点（/metrics、/health、/stats）的监听配置。
type Metrics struct {
	Listen string `yaml:"listen"` // host:port，空 = 不启用
}

// DNS 是 proxy-client 可选的内置 DNS 网关配置（路线图 3.1）。
//
// listen 为空时网关关闭。开启后：分流为 proxy 的名字经出口节点远程解析
// （DNS over TCP 走隧道），分流为 direct 的名字转发给本机解析器（local，
// 缺省读取 /etc/resolv.conf）。仅允许监听环回地址，避免成为开放解析器。
type DNS struct {
	Listen  string   `yaml:"listen"`  // host:port，空 = 关闭；仅允许环回地址
	Remote  string   `yaml:"remote"`  // 经出口节点访问的 DNS 服务器，缺省 1.1.1.1:53
	Local   []string `yaml:"local"`   // 直连名字使用的本机解析器；空 = 读取 /etc/resolv.conf
	Timeout Duration `yaml:"timeout"` // 单次查询超时，缺省 5s
}

// DNS 网关缺省值。
const (
	defaultDNSRemote  = "1.1.1.1:53"
	defaultDNSTimeout = 5 * time.Second
)

// EffectiveRemote 返回生效的远程解析服务器（缺省 1.1.1.1:53）。
func (d DNS) EffectiveRemote() string {
	if strings.TrimSpace(d.Remote) == "" {
		return defaultDNSRemote
	}
	return d.Remote
}

// EffectiveTimeout 返回生效的单次查询超时（缺省 5s）。
func (d DNS) EffectiveTimeout() time.Duration {
	if d.Timeout <= 0 {
		return defaultDNSTimeout
	}
	return d.Timeout.Std()
}

// Log 是日志配置。
type Log struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // json | text
}

// Client 是 proxy-client 的完整配置。
type Client struct {
	Inbound     Inbound     `yaml:"inbound"`
	Nodes       []Node      `yaml:"nodes"`
	Pool        Pool        `yaml:"pool"`
	HealthCheck HealthCheck `yaml:"health_check"`
	Limits      Limits      `yaml:"limits"`
	TLS         ClientTLS   `yaml:"tls"`
	Routing     Routing     `yaml:"routing"`
	DNS         DNS         `yaml:"dns"`
	Timeouts    Timeouts    `yaml:"timeouts"`
	Metrics     Metrics     `yaml:"metrics"`
	Log         Log         `yaml:"log"`
}

// Server 是 proxy-server 的完整配置。
type Server struct {
	Listen    string    `yaml:"listen"`
	TLS       ServerTLS `yaml:"tls"`
	Users     []User    `yaml:"users"`
	DecoyFile string    `yaml:"decoy_file"` // 可选：认证失败时的伪装页面
	Limits    Limits    `yaml:"limits"`
	Timeouts  Timeouts  `yaml:"timeouts"`
	Metrics   Metrics   `yaml:"metrics"`
	Log       Log       `yaml:"log"`
}

// LoadClient 从 path 读取、解析并校验客户端配置。
func LoadClient(path string) (*Client, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client config: %w", err)
	}
	cfg, err := ParseClient(data)
	if err != nil {
		return nil, fmt.Errorf("client config %s: %w", path, err)
	}
	return cfg, nil
}

// ParseClient 解析客户端配置 YAML，应用默认值并校验。
func ParseClient(data []byte) (*Client, error) {
	var cfg Client
	if err := decodeStrict(data, &cfg); err != nil {
		return nil, err
	}
	// 在应用缺省值之前检查：dns 字段存在但 listen 为空说明用户意图被静默吞掉。
	if err := cfg.DNS.validateBeforeDefaults(); err != nil {
		return nil, err
	}
	if err := cfg.Routing.validateBeforeDefaults(); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadServer 从 path 读取、解析并校验服务端配置。
func LoadServer(path string) (*Server, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server config: %w", err)
	}
	cfg, err := ParseServer(data)
	if err != nil {
		return nil, fmt.Errorf("server config %s: %w", path, err)
	}
	return cfg, nil
}

// ParseServer 解析服务端配置 YAML，应用默认值并校验。
func ParseServer(data []byte) (*Server, error) {
	var cfg Server
	if err := decodeStrict(data, &cfg); err != nil {
		return nil, err
	}
	// timeouts.failover 只对 proxy-client 有意义（出口节点故障转移链）；
	// 服务端显式配置时报错，避免无效配置被静默接受。
	if cfg.Timeouts.Failover != 0 {
		return nil, errors.New("timeouts.failover: only supported by proxy-client")
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ClientRestartOnlyChanges 返回两份已解析客户端配置之间、需要重启才能生效的字段。
//
// 这些字段对应进程启动时绑定的监听资源（socket），热加载无法在不打断
// 存量连接的前提下原子替换；配置热加载遇到此类变更时拒绝整份新配置，
// 保持旧配置继续服务，并提示需要重启。
func ClientRestartOnlyChanges(old, next *Client) []string {
	var changed []string
	if old.Inbound.HTTP != next.Inbound.HTTP {
		changed = append(changed, "inbound.http")
	}
	if old.Inbound.SOCKS5 != next.Inbound.SOCKS5 {
		changed = append(changed, "inbound.socks5")
	}
	if old.Metrics.Listen != next.Metrics.Listen {
		changed = append(changed, "metrics.listen")
	}
	if old.DNS.Listen != next.DNS.Listen {
		changed = append(changed, "dns.listen")
	}
	return changed
}

// ServerRestartOnlyChanges 返回两份已解析服务端配置之间、需要重启才能生效的字段。
func ServerRestartOnlyChanges(old, next *Server) []string {
	var changed []string
	if old.Listen != next.Listen {
		changed = append(changed, "listen")
	}
	if old.Metrics.Listen != next.Metrics.Listen {
		changed = append(changed, "metrics.listen")
	}
	return changed
}

func decodeStrict(data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("config is empty")
		}
		return fmt.Errorf("parse yaml: %w", err)
	}
	return nil
}

func (c *Client) applyDefaults() {
	applyTimeoutDefaults(&c.Timeouts)
	if c.Timeouts.Failover == 0 {
		c.Timeouts.Failover = Duration(defaultFailoverBudget)
	}
	if c.Pool.MaxIdle == nil {
		c.Pool.MaxIdle = intPtr(defaultPoolMaxIdle)
	}
	if c.Pool.IdleTTL == 0 {
		c.Pool.IdleTTL = Duration(defaultPoolIdleTTL)
	}
	if c.HealthCheck.Interval == nil {
		c.HealthCheck.Interval = durationPtr(defaultHealthInterval)
	}
	if c.HealthCheck.Timeout == 0 {
		c.HealthCheck.Timeout = Duration(defaultHealthTimeout)
	}
	if c.HealthCheck.Failures == nil {
		c.HealthCheck.Failures = intPtr(defaultHealthFailures)
	}
	if c.HealthCheck.Successes == nil {
		c.HealthCheck.Successes = intPtr(defaultHealthSuccesses)
	}
	if c.Limits.MaxConnections == nil {
		c.Limits.MaxConnections = intPtr(defaultMaxConnections)
	}
	if strings.TrimSpace(c.Routing.Default) == "" {
		c.Routing.Default = "proxy"
	}
	if c.Routing.RulesURL != "" && c.Routing.RulesRefreshInterval == nil {
		c.Routing.RulesRefreshInterval = durationPtr(defaultRulesRefreshInterval)
	}
	if c.Routing.PrivateDirect == nil {
		c.Routing.PrivateDirect = boolPtr(true)
	}
	if strings.TrimSpace(c.DNS.Remote) == "" {
		c.DNS.Remote = defaultDNSRemote
	}
	if c.DNS.Timeout <= 0 {
		c.DNS.Timeout = Duration(defaultDNSTimeout)
	}
	applyLogDefaults(&c.Log)
}

func (s *Server) applyDefaults() {
	applyTimeoutDefaults(&s.Timeouts)
	if s.Limits.MaxConnections == nil {
		s.Limits.MaxConnections = intPtr(defaultMaxConnections)
	}
	applyLogDefaults(&s.Log)
}

func applyTimeoutDefaults(t *Timeouts) {
	if t.Dial == 0 {
		t.Dial = Duration(10 * time.Second)
	}
	if t.Handshake == 0 {
		t.Handshake = Duration(10 * time.Second)
	}
	if t.Idle == 0 {
		t.Idle = Duration(90 * time.Second)
	}
	if t.Shutdown == 0 {
		t.Shutdown = Duration(shutdown.DefaultTimeout)
	}
}

func applyLogDefaults(l *Log) {
	if strings.TrimSpace(l.Level) == "" {
		l.Level = "info"
	}
	if strings.TrimSpace(l.Format) == "" {
		l.Format = "json"
	}
}

func (c *Client) validate() error {
	if err := validateLog(c.Log); err != nil {
		return err
	}
	if err := validateMetrics(c.Metrics); err != nil {
		return err
	}
	if err := validateTimeouts(c.Timeouts); err != nil {
		return err
	}
	if c.Timeouts.Failover <= 0 {
		return errors.New("timeouts.failover: must be positive")
	}
	if c.Pool.EffectiveMaxIdle() < 0 {
		return errors.New("pool.max_idle: must not be negative (0 disables the pool)")
	}
	if c.Pool.IdleTTL < 0 {
		return errors.New("pool.idle_ttl: must not be negative")
	}
	if c.HealthCheck.Interval != nil && c.HealthCheck.Interval.Std() < 0 {
		return errors.New("health_check.interval: must not be negative (0 disables active probing)")
	}
	if c.HealthCheck.Timeout.Std() < 0 {
		return errors.New("health_check.timeout: must not be negative")
	}
	if c.HealthCheck.Failures != nil && *c.HealthCheck.Failures < 1 {
		return errors.New("health_check.failures: must be >= 1")
	}
	if c.HealthCheck.Successes != nil && *c.HealthCheck.Successes < 1 {
		return errors.New("health_check.successes: must be >= 1")
	}
	if c.Limits.EffectiveMaxConnections() < 0 {
		return errors.New("limits.max_connections: must not be negative (0 disables the limit)")
	}

	if c.Inbound.HTTP == "" && c.Inbound.SOCKS5 == "" {
		return errors.New("inbound: at least one of http/socks5 must be configured")
	}
	if c.Inbound.HTTP != "" {
		if err := validateListenAddr("inbound.http", c.Inbound.HTTP); err != nil {
			return err
		}
		if len(c.Inbound.Auth) == 0 && !isLoopbackListen(c.Inbound.HTTP) {
			return fmt.Errorf("inbound.http: listening on non-loopback address %q requires inbound.auth", c.Inbound.HTTP)
		}
	}
	if c.Inbound.SOCKS5 != "" {
		if err := validateListenAddr("inbound.socks5", c.Inbound.SOCKS5); err != nil {
			return err
		}
		if len(c.Inbound.Auth) == 0 && !isLoopbackListen(c.Inbound.SOCKS5) {
			return fmt.Errorf("inbound.socks5: listening on non-loopback address %q requires inbound.auth", c.Inbound.SOCKS5)
		}
	}
	if err := validateUsers("inbound.auth", c.Inbound.Auth, false); err != nil {
		return err
	}
	if err := validateDNS(c.DNS); err != nil {
		return err
	}

	action := strings.ToLower(strings.TrimSpace(c.Routing.Default))
	if action != "direct" && action != "proxy" {
		return fmt.Errorf("routing.default: invalid value %q: want direct or proxy", c.Routing.Default)
	}
	c.Routing.Default = action
	if err := validateRulesURL(c.Routing.RulesURL); err != nil {
		return err
	}
	if c.Routing.RulesRefreshInterval != nil && c.Routing.RulesRefreshInterval.Std() < 0 {
		return errors.New("routing.rules_refresh_interval: must not be negative (0 fetches once at startup)")
	}
	if action == "proxy" && len(c.Nodes) == 0 {
		return errors.New("nodes: at least one exit node is required when routing.default is proxy")
	}
	for i := range c.Nodes {
		node := &c.Nodes[i]
		if err := validateHostPort(fmt.Sprintf("nodes[%d].addr", i), node.Addr); err != nil {
			return err
		}
		if node.Password == "" {
			return fmt.Errorf("nodes[%d].password: must not be empty", i)
		}
		if strings.ContainsAny(node.Password+node.SNI, "\r\n") {
			return fmt.Errorf("nodes[%d]: password/sni must not contain CR or LF", i)
		}
	}
	return nil
}

func (s *Server) validate() error {
	if err := validateLog(s.Log); err != nil {
		return err
	}
	if err := validateMetrics(s.Metrics); err != nil {
		return err
	}
	if err := validateTimeouts(s.Timeouts); err != nil {
		return err
	}
	if s.Listen == "" {
		return errors.New("listen: must not be empty")
	}
	if err := validateListenAddr("listen", s.Listen); err != nil {
		return err
	}
	if s.TLS.CertFile == "" || s.TLS.KeyFile == "" {
		return errors.New("tls: cert_file and key_file are required")
	}
	if s.Limits.EffectiveMaxConnections() < 0 {
		return errors.New("limits.max_connections: must not be negative (0 disables the limit)")
	}
	return validateUsers("users", s.Users, true)
}

func validateUsers(what string, users []User, required bool) error {
	if len(users) == 0 {
		if required {
			return fmt.Errorf("%s: at least one user is required", what)
		}
		return nil
	}
	seen := make(map[string]bool, len(users))
	for i, u := range users {
		if strings.TrimSpace(u.Username) == "" {
			return fmt.Errorf("%s[%d]: username must not be empty", what, i)
		}
		if u.Password == "" {
			return fmt.Errorf("%s[%d] (%s): password must not be empty", what, i, u.Username)
		}
		if strings.ContainsAny(u.Username+u.Password, "\r\n") {
			return fmt.Errorf("%s[%d] (%s): username/password must not contain CR or LF", what, i, u.Username)
		}
		if seen[u.Username] {
			return fmt.Errorf("%s: duplicate username %q", what, u.Username)
		}
		seen[u.Username] = true
	}
	return nil
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

func validateMetrics(m Metrics) error {
	if m.Listen == "" {
		return nil
	}
	return validateListenAddr("metrics.listen", m.Listen)
}

// validateBeforeDefaults 在应用缺省值之前检查 dns 段：字段存在但 listen 为空
// 会让配置静默失效，按严格解析的原则直接报错。
func (d DNS) validateBeforeDefaults() error {
	if d.Listen == "" && (d.Remote != "" || len(d.Local) > 0 || d.Timeout != 0) {
		return errors.New("dns.listen is empty (DNS gateway disabled): remove the dns section or set dns.listen")
	}
	return nil
}

// validateBeforeDefaults 在应用缺省值之前检查 routing 段：规则源互斥、
// 刷新周期只对远程规则有意义，避免配置意图被静默吞掉。
func (r Routing) validateBeforeDefaults() error {
	if r.RulesFile != "" && r.RulesURL != "" {
		return errors.New("routing: configure only one of rules_file (local) and rules_url (remote)")
	}
	if r.RulesURL == "" && r.RulesRefreshInterval != nil {
		return errors.New("routing.rules_refresh_interval is set but routing.rules_url is empty (the interval only applies to remote rules)")
	}
	return nil
}

// validateRulesURL 校验远程规则 URL：空值合法（未启用），其余仅允许 http/https 且必须有主机。
func validateRulesURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("routing.rules_url: invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("routing.rules_url: unsupported scheme %q: want http or https", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("routing.rules_url: missing host in %q", raw)
	}
	return nil
}

// validateDNS 校验 DNS 网关配置（缺省值已应用）。
func validateDNS(d DNS) error {
	if d.Listen == "" {
		return nil
	}
	if err := validateListenAddr("dns.listen", d.Listen); err != nil {
		return err
	}
	if !isLoopbackListen(d.Listen) {
		return fmt.Errorf("dns.listen: only loopback addresses are allowed (got %q): refusing to run as an open resolver", d.Listen)
	}
	if err := validateHostPort("dns.remote", d.Remote); err != nil {
		return err
	}
	for i, addr := range d.Local {
		what := fmt.Sprintf("dns.local[%d]", i)
		if err := validateHostPort(what, addr); err != nil {
			return err
		}
		if netutil.SameHostPort(addr, d.Listen) {
			return fmt.Errorf("%s: %q points to the DNS gateway itself", what, addr)
		}
	}
	return nil
}

func validateTimeouts(t Timeouts) error {
	if t.Dial <= 0 {
		return errors.New("timeouts.dial: must be positive")
	}
	if t.Handshake <= 0 {
		return errors.New("timeouts.handshake: must be positive")
	}
	if t.Idle <= 0 {
		return errors.New("timeouts.idle: must be positive")
	}
	if t.Shutdown <= 0 {
		return errors.New("timeouts.shutdown: must be positive")
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

// isLoopbackListen 判断监听地址是否仅绑定本机环回接口。
// 无法确认（空 host、主机名）时按非环回处理，从严要求认证。
func isLoopbackListen(addr string) bool {
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

func boolPtr(b bool) *bool { return &b }

func intPtr(v int) *int { return &v }

func durationPtr(d time.Duration) *Duration {
	v := Duration(d)
	return &v
}
