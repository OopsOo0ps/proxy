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
	"os"
	"strconv"
	"strings"
	"time"

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

// Inbound 描述本机入站代理监听。
type Inbound struct {
	HTTP   string `yaml:"http"`   // host:port，空 = 不启用
	SOCKS5 string `yaml:"socks5"` // host:port，空 = 不启用
	Auth   []User `yaml:"auth"`   // 凭据列表；监听非环回地址时必填
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

// Routing 是分流配置。
type Routing struct {
	Default       string `yaml:"default"`        // direct | proxy，缺省 proxy
	RulesFile     string `yaml:"rules_file"`     // 可选：规则文件路径
	PrivateDirect *bool  `yaml:"private_direct"` // 环回/私网目标直连，缺省 true
}

// Timeouts 是各类超时。
type Timeouts struct {
	Dial      Duration `yaml:"dial"`      // 建立目标/节点连接
	Handshake Duration `yaml:"handshake"` // 隧道握手（TLS + Trojan）
	Idle      Duration `yaml:"idle"`      // 连接空闲回收
}

// Metrics 是运维端点（/metrics、/health、/stats）的监听配置。
type Metrics struct {
	Listen string `yaml:"listen"` // host:port，空 = 不启用
}

// Log 是日志配置。
type Log struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // json | text
}

// Client 是 proxy-client 的完整配置。
type Client struct {
	Inbound  Inbound   `yaml:"inbound"`
	Nodes    []Node    `yaml:"nodes"`
	TLS      ClientTLS `yaml:"tls"`
	Routing  Routing   `yaml:"routing"`
	Timeouts Timeouts  `yaml:"timeouts"`
	Metrics  Metrics   `yaml:"metrics"`
	Log      Log       `yaml:"log"`
}

// Server 是 proxy-server 的完整配置。
type Server struct {
	Listen    string    `yaml:"listen"`
	TLS       ServerTLS `yaml:"tls"`
	Users     []User    `yaml:"users"`
	DecoyFile string    `yaml:"decoy_file"` // 可选：认证失败时的伪装页面
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
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
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
	if strings.TrimSpace(c.Routing.Default) == "" {
		c.Routing.Default = "proxy"
	}
	if c.Routing.PrivateDirect == nil {
		c.Routing.PrivateDirect = boolPtr(true)
	}
	applyLogDefaults(&c.Log)
}

func (s *Server) applyDefaults() {
	applyTimeoutDefaults(&s.Timeouts)
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

	action := strings.ToLower(strings.TrimSpace(c.Routing.Default))
	if action != "direct" && action != "proxy" {
		return fmt.Errorf("routing.default: invalid value %q: want direct or proxy", c.Routing.Default)
	}
	c.Routing.Default = action
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
