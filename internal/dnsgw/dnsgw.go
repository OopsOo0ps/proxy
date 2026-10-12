// Package dnsgw 实现 proxy-client 可选的内置 DNS 网关（本机环回监听 UDP/TCP）。
//
// 设计目标（路线图 3.1：DNS 处理策略）：让 DNS 查询与流量走同一条路径——
//   - 分流决策为 proxy 的名字：查询经出口节点远程解析（DNS over TCP 走
//     Trojan 隧道），由出口侧发起解析，本机不解析、不泄漏；
//   - 分流决策为 direct 的名字：转发给本机配置的解析器（缺省读取
//     /etc/resolv.conf），保持内网 / 直连语义。
//
// 该网关是“显式代理入站”的补充而非替代：应用直接把域名交给代理
// （HTTP CONNECT 、socks5h）时，域名本就随隧道到出口解析，无需经过这里；
// 网关面向的是“先做 DNS、再连 IP”的应用与系统级解析（resolv.conf /
// systemd-resolved 指向本网关）。
package dnsgw

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/netutil"
	"github.com/OopsOo0ps/proxy/internal/routing"
	"github.com/OopsOo0ps/proxy/internal/shutdown"
)

const (
	// DefaultRemote 是缺省的远程解析服务器（经出口节点，DNS over TCP）。
	// 应选择从出口可达、支持 TCP 的解析器；必要时在配置中覆盖。
	DefaultRemote = "1.1.1.1:53"

	// DefaultResolvConfPath 是缺省的系统解析器配置文件路径。
	DefaultResolvConfPath = "/etc/resolv.conf"

	// DefaultTimeout 是单次查询（含上游往返）的缺省超时。
	DefaultTimeout = 5 * time.Second

	// maxUDPPayload 是收发的 UDP 报文上限（覆盖 EDNS0 常用缓冲 4096）。
	maxUDPPayload = 4096
)

// RouteDecider 返回名字的分流动作（与流量分流共用同一引擎，保证
// “DNS 走哪条路 = 流量走哪条路”）。
type RouteDecider interface {
	Decide(host string) routing.Action
}

// LivePolicy 提供配置热加载后的动态解析策略。
// 为 nil 时使用 Server 构造时的静态字段（测试与直接构造场景）。
type LivePolicy interface {
	// Router 返回当前分流引擎。
	Router() RouteDecider
	// Remote 返回当前远程解析服务器（host:port）。
	Remote() string
	// Local 返回当前本机解析器列表；为空表示不可用。
	Local() []string
	// Timeout 返回当前单次查询超时。
	Timeout() time.Duration
	// ShutdownTimeout 返回关停排空期限。
	ShutdownTimeout() time.Duration
}

// ProxyDialer 强制经出口节点建立 TCP 连接的拨号能力（core.ProxyDialer）；
// 返回的 core.Route 供日志的 upstream 字段使用，本包不再自造标签词汇。
type ProxyDialer = core.ProxyDialer

// ResultInvalid 是被网关拒绝 / 丢弃的非法查询（未转发给任何上游）的
// 结果标签值；route/result 的其余取值与 core.Telemetry 的请求观测共享
// 词汇（DNS 走哪条路 = 流量走哪条路），本包只补充 DNS 特有的拒绝语义。
const ResultInvalid = "invalid"

// DNSObserver 是 DNS 网关的遥测出口；*metrics.Metrics 适配实现（L4 单点）。
type DNSObserver interface {
	// QueryDone 记录一次查询（含失败与被拒绝的非法查询）。
	// route 取值 core.RouteDirect / core.RouteProxy / core.RouteNone；
	// 耗时是否按路径统计由实现决定（Prometheus 适配只统计实际转发路径）。
	QueryDone(route, result string, d time.Duration)
}

// NopObserver 是 Options 的缺省遥测出口：全部方法为空操作，
// 组件测试零构造、无需 registry。
var NopObserver DNSObserver = nopObserver{}

type nopObserver struct{}

func (nopObserver) QueryDone(string, string, time.Duration) {}

// Options 是 Server 构造参数。
type Options struct {
	// ListenAddr 是网关监听地址，仅用于日志与自环排除（实际 bind 见 Listen）。
	ListenAddr string
	// Remote 是经出口节点访问的 DNS 服务器（host:port），缺省 DefaultRemote。
	Remote string
	// Local 是直连名字使用的本机解析器列表；为空时读取 ResolvConfPath
	// （启用 Live 时由调用方负责解析生效列表，构造器不做缺省读取）。
	Local []string
	// Timeout 是单次查询超时，缺省 DefaultTimeout。
	Timeout time.Duration
	// ResolvConfPath 是系统解析器配置路径，缺省 DefaultResolvConfPath。
	ResolvConfPath string
	// Router 分流引擎（必填）。
	Router RouteDecider
	// ProxyDialer 经出口节点的拨号能力（必填）。
	ProxyDialer ProxyDialer
	// Logger 日志；为 nil 时静默。
	Logger *slog.Logger
	// Observer 是遥测出口；nil 时使用 NopObserver。
	Observer DNSObserver
	// ShutdownTimeout 关停时等待存量查询结束的最长时间，缺省 15s。
	ShutdownTimeout time.Duration
	// Live 提供热加载后的动态解析策略；非 nil 时优先于上方静态选项。
	Live LivePolicy
}

// Server 是 DNS 网关。
type Server struct {
	remote          string
	local           []string
	timeout         time.Duration
	router          RouteDecider
	proxyDialer     ProxyDialer
	logger          *slog.Logger
	observer        DNSObserver
	shutdownTimeout time.Duration
	direct          *net.Dialer // 直连本机解析器
	live            LivePolicy
}

// New 校验参数、补齐缺省值并构造网关。
func New(opts Options) (*Server, error) {
	if opts.Router == nil {
		return nil, errors.New("dnsgw: router is required")
	}
	if opts.ProxyDialer == nil {
		return nil, errors.New("dnsgw: proxy dialer is required")
	}
	observer := opts.Observer
	if observer == nil {
		observer = NopObserver
	}
	s := &Server{
		remote:          opts.Remote,
		timeout:         opts.Timeout,
		router:          opts.Router,
		proxyDialer:     opts.ProxyDialer,
		logger:          opts.Logger,
		observer:        observer,
		shutdownTimeout: opts.ShutdownTimeout,
		live:            opts.Live,
	}
	if s.remote == "" {
		s.remote = DefaultRemote
	}
	if _, _, err := net.SplitHostPort(s.remote); err != nil {
		return nil, fmt.Errorf("dnsgw: invalid remote resolver %q: %w", s.remote, err)
	}
	if s.timeout <= 0 {
		s.timeout = DefaultTimeout
	}
	s.direct = &net.Dialer{Timeout: s.timeout}

	local := opts.Local
	for _, addr := range local {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("dnsgw: invalid local resolver %q: %w", addr, err)
		}
	}
	// Live 启用时缺省解析由调用方在快照构建阶段完成（可随热加载更新）。
	if len(local) == 0 && opts.Live == nil {
		path := opts.ResolvConfPath
		if path == "" {
			path = DefaultResolvConfPath
		}
		resolved, err := LocalResolversFromResolvConf(path, opts.ListenAddr)
		switch {
		case err != nil:
			s.log().Warn("dns gateway: cannot read system resolvers, direct-routed names will fail",
				"path", path, "error", err)
		case len(resolved) == 0:
			s.log().Warn("dns gateway: no usable system resolvers found, direct-routed names will fail",
				"path", path, "hint", "set dns.local explicitly")
		default:
			s.log().Info("dns gateway: using system resolvers for direct-routed names",
				"path", path, "resolvers", resolved)
			local = resolved
		}
	}
	s.local = local
	return s, nil
}

// Listener 是同一地址上的 UDP 与 TCP 双协议监听。
type Listener struct {
	UDP *net.UDPConn
	TCP net.Listener
}

// Addr 返回监听地址（以 TCP 侧为准）。
func (l *Listener) Addr() net.Addr { return l.TCP.Addr() }

// Close 关闭两个监听。
func (l *Listener) Close() error {
	err := l.TCP.Close()
	if uerr := l.UDP.Close(); err == nil {
		err = uerr
	}
	return err
}

// Listen 绑定 addr 的 UDP 与 TCP 监听（DNS 标准的双协议入口）。
// 端口为 0 时用 TCP 实际选中的端口绑定 UDP，保证两侧同端口。
func Listen(addr string) (*Listener, error) {
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dnsgw: listen tcp %s: %w", addr, err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", tcpLn.Addr().String())
	if err != nil {
		_ = tcpLn.Close()
		return nil, fmt.Errorf("dnsgw: resolve udp %s: %w", tcpLn.Addr(), err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_ = tcpLn.Close()
		return nil, fmt.Errorf("dnsgw: listen udp %s: %w", tcpLn.Addr(), err)
	}
	return &Listener{UDP: udpConn, TCP: tcpLn}, nil
}

// Serve 在 l 上提供 DNS 服务；ctx 取消后按与其它组件一致的语义优雅关停：
// 先停止接受新查询，让存量查询在关停期限内自然结束，超时后强制中断。
func (s *Server) Serve(ctx context.Context, l *Listener) error {
	// queryCtx 与关停信号解耦：收到关停后存量查询继续完成，
	// 只有超过关停期限（forceCancel）才被打断。
	queryCtx, forceCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer forceCancel()

	var wg sync.WaitGroup
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
		case <-done:
		}
	}()

	tcpErrCh := make(chan error, 1)
	go func() { tcpErrCh <- s.serveTCP(queryCtx, l.TCP, &wg) }()

	udpErr := s.serveUDP(queryCtx, l.UDP, &wg)
	// UDP 循环退出（正常关停或致命错误）后一并停止 TCP 侧。
	_ = l.Close()
	tcpErr := <-tcpErrCh

	if ctx.Err() != nil {
		s.log().Info("shutdown: stopped accepting new DNS queries",
			"drain_timeout", s.shutdownTimeoutOrDefault().String())
		if shutdown.Wait(&wg, s.shutdownTimeoutOrDefault(), forceCancel) {
			s.log().Info("shutdown: all in-flight DNS queries drained")
		} else {
			s.log().Warn("shutdown: timeout exceeded, remaining DNS queries closed")
		}
		return nil
	}
	forceCancel()
	wg.Wait()
	if udpErr != nil {
		return udpErr
	}
	return tcpErr
}

// serveUDP 读取 UDP 查询并分发处理。
func (s *Server) serveUDP(ctx context.Context, pc *net.UDPConn, wg *sync.WaitGroup) error {
	buf := make([]byte, maxUDPPayload)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("dnsgw: read udp: %w", err)
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := s.handleQuery(ctx, payload, net.UDPAddrFromAddrPort(from))
			if resp == nil {
				return
			}
			_ = pc.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = pc.WriteToUDPAddrPort(resp, from)
		}()
	}
}

// serveTCP 接受 TCP 连接；每条连接可顺序承载多条查询（RFC 1035 长度前缀）。
func (s *Server) serveTCP(ctx context.Context, ln net.Listener, wg *sync.WaitGroup) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("dnsgw: accept tcp: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleTCPConn(ctx, conn)
		}()
	}
}

func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.timeoutNow()))
		payload, err := readFrame(br)
		if err != nil {
			return
		}
		resp := s.handleQuery(ctx, payload, conn.RemoteAddr())
		if resp == nil {
			// 非查询报文：不再等待同连接上的后续查询。
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(s.timeoutNow()))
		if err := writeFrame(conn, resp); err != nil {
			if !errors.Is(err, io.ErrClosedPipe) {
				s.log().Debug("dns gateway: write tcp response failed", "error", err)
			}
			return
		}
	}
}

// handleQuery 处理一条查询并返回响应报文；resp 为 nil 表示不响应（静默丢弃）。
func (s *Server) handleQuery(ctx context.Context, payload []byte, from net.Addr) []byte {
	start := time.Now()
	logger := s.log().With(
		"request_id", logging.NewRequestID(),
		"proto", "dns",
		"client_ip", netutil.RemoteIP(from),
	)

	q, err := parseQuery(payload)
	if err != nil {
		return s.handleInvalid(logger, payload, err, start)
	}

	route := core.RouteProxy
	var (
		resp     []byte
		upstream string
	)
	if s.routerNow().Decide(q.name) == routing.Direct {
		route = core.RouteDirect
		resp, upstream, err = s.queryLocal(ctx, q)
	} else {
		resp, upstream, err = s.queryRemote(ctx, q)
	}

	result := core.ResultOK
	if err != nil {
		result = core.ResultError
		logger.Warn("dns query failed",
			"name", q.name, "qtype", typeName(q.qtype), "route", route, "error", err)
		resp = errorResponseEcho(q, rcodeServerFail)
	}
	elapsed := time.Since(start)
	s.observer.QueryDone(route, result, elapsed)
	logger.Info("dns query completed",
		"name", q.name,
		"qtype", typeName(q.qtype),
		"route", route,
		"upstream", upstream,
		"answer_bytes", len(resp),
		"duration", elapsed.Round(time.Microsecond).String(),
		"duration_ms", elapsed.Milliseconds(),
		"result", result,
	)
	return resp
}

// handleInvalid 处理无法转发的报文：响应报文静默丢弃；其它按错误分类回
// FORMERR / REFUSED，不计入解析器往返（routes=none）。
func (s *Server) handleInvalid(logger *slog.Logger, payload []byte, err error, start time.Time) []byte {
	result := ResultInvalid
	defer func() { s.observer.QueryDone(core.RouteNone, result, time.Since(start)) }()

	switch {
	case errors.Is(err, errNotQuery):
		// 收到响应报文（例如误配置成的转发环）：丢弃，避免打环。
		logger.Debug("dns gateway: dropping response message")
		return nil
	case errors.Is(err, errBadOpcode), errors.Is(err, errNoSingleQuestion):
		logger.Debug("dns gateway: refusing unsupported query", "error", err)
		return errorResponse(payload, rcodeRefused)
	default:
		logger.Debug("dns gateway: dropping malformed message", "error", err)
		return errorResponse(payload, rcodeFormatErr)
	}
}

// queryLocal 依次尝试本机解析器（UDP 优先；截断时按 RFC 1035 改走 TCP）。
func (s *Server) queryLocal(ctx context.Context, q query) ([]byte, string, error) {
	local := s.localNow()
	if len(local) == 0 {
		return nil, "", errors.New("no local resolvers available")
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeoutNow())
	defer cancel()

	var errs []error
	for _, upstream := range local {
		resp, err := s.exchangeUDP(ctx, upstream, q)
		if err == nil && !isTruncated(resp) {
			return resp, upstream, nil
		}
		if err == nil {
			tcpResp, tcpErr := s.exchangeLocalTCP(ctx, upstream, q)
			if tcpErr == nil {
				return tcpResp, upstream, nil
			}
			err = fmt.Errorf("tcp retry after truncation: %w", tcpErr)
		}
		errs = append(errs, fmt.Errorf("%s: %w", upstream, err))
	}
	return nil, "", fmt.Errorf("all local resolvers failed: %w", errors.Join(errs...))
}

// queryRemote 经出口节点访问远程解析器（DNS over TCP，走 Trojan 隧道）。
func (s *Server) queryRemote(ctx context.Context, q query) ([]byte, string, error) {
	remote := s.remoteNow()
	host, portString, err := net.SplitHostPort(remote)
	if err != nil {
		return nil, "", fmt.Errorf("remote resolver %q: %w", remote, err)
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil || port == 0 {
		return nil, "", fmt.Errorf("remote resolver %q: invalid port", remote)
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeoutNow())
	defer cancel()

	conn, route, err := s.proxyDialer.DialProxy(ctx, core.Target{Host: host, Port: uint16(port)})
	if err != nil {
		return nil, "", fmt.Errorf("dial remote resolver %s via exit node: %w", remote, err)
	}
	label := route.Label()
	defer func() { _ = conn.Close() }()
	setDeadlineFromCtx(conn, ctx, s.timeoutNow())

	if err := writeFrame(conn, q.payload); err != nil {
		return nil, label, fmt.Errorf("write to remote resolver: %w", err)
	}
	resp, err := readFrame(conn)
	if err != nil {
		return nil, label, fmt.Errorf("read from remote resolver: %w", err)
	}
	if !validResponse(q.id, resp) {
		return nil, label, errors.New("invalid response from remote resolver")
	}
	return resp, label, nil
}

// exchangeUDP 通过一次性的本地 UDP 套接字与上游交换报文。
func (s *Server) exchangeUDP(ctx context.Context, upstream string, q query) ([]byte, error) {
	conn, err := s.directNow().DialContext(ctx, "udp", upstream)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	setDeadlineFromCtx(conn, ctx, s.timeoutNow())

	if _, err := conn.Write(q.payload); err != nil {
		return nil, err
	}
	buf := make([]byte, maxUDPPayload)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	resp := buf[:n]
	if !validResponse(q.id, resp) {
		return nil, errors.New("invalid response from local resolver")
	}
	return resp, nil
}

// exchangeLocalTCP 经 TCP 与本机解析器交换报文（UDP 截断后的重试路径）。
func (s *Server) exchangeLocalTCP(ctx context.Context, upstream string, q query) ([]byte, error) {
	conn, err := s.directNow().DialContext(ctx, "tcp", upstream)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	setDeadlineFromCtx(conn, ctx, s.timeoutNow())

	if err := writeFrame(conn, q.payload); err != nil {
		return nil, err
	}
	resp, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	if !validResponse(q.id, resp) {
		return nil, errors.New("invalid response from local resolver")
	}
	return resp, nil
}

// setDeadlineFromCtx 依据 ctx 的期限设置连接截止时间；无期限时回退到 timeout。
func setDeadlineFromCtx(conn net.Conn, ctx context.Context, timeout time.Duration) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
		return
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
}

// readFrame 读取一个 DNS over TCP 长度前缀帧（RFC 1035 4.2.2）。
func readFrame(r io.Reader) ([]byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(head[:]))
	if n == 0 {
		return nil, errors.New("dnsgw: empty frame")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeFrame 写出一个 DNS over TCP 长度前缀帧。
//
// 必须单次写出（前缀与载荷同一次 Write）：分两次写时，2 字节的前缀会立即
// 成段，而载荷受 Nagle 算法影响要等前缀的 ACK（约一个 RTT）才发出；部分
// 解析器/中间设备对“只收到长度前缀”的连接会直接重置，导致 DNS over TCP
// 偶发失败（本仓库在阿里云 VPS 实测到该现象）。
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > 0xFFFF {
		return errors.New("dnsgw: message exceeds 65535 bytes")
	}
	buf := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(payload)))
	copy(buf[2:], payload)
	_, err := w.Write(buf)
	return err
}

// LocalResolversFromResolvConf 解析 nameserver 行返回 host:port 列表，
// 排除 exclude（网关自身监听地址，防止把查询转发给自己形成自环）。
// 供 Server 构造与配置热加载共用。
func LocalResolversFromResolvConf(path, exclude string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		addr := net.JoinHostPort(ip.String(), "53")
		if exclude != "" && netutil.SameHostPort(addr, exclude) {
			continue
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out, nil
}

func (s *Server) log() *slog.Logger {
	if s.logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.logger
}

// routerNow 返回当前生效的分流引擎：Live 存在时以热加载快照为准。
func (s *Server) routerNow() RouteDecider {
	if s.live != nil {
		return s.live.Router()
	}
	return s.router
}

// remoteNow 返回当前生效的远程解析服务器。
func (s *Server) remoteNow() string {
	if s.live != nil {
		if remote := s.live.Remote(); remote != "" {
			return remote
		}
	}
	return s.remote
}

// localNow 返回当前生效的本机解析器列表。
func (s *Server) localNow() []string {
	if s.live != nil {
		return s.live.Local()
	}
	return s.local
}

// timeoutNow 返回当前生效的单次查询超时（非法值回退缺省）。
func (s *Server) timeoutNow() time.Duration {
	if s.live != nil {
		if timeout := s.live.Timeout(); timeout > 0 {
			return timeout
		}
	}
	if s.timeout <= 0 {
		return DefaultTimeout
	}
	return s.timeout
}

// directNow 返回直连本机解析器的拨号器；超时取自当前快照。
func (s *Server) directNow() *net.Dialer {
	if s.live != nil {
		return &net.Dialer{Timeout: s.timeoutNow()}
	}
	return s.direct
}

func (s *Server) shutdownTimeoutOrDefault() time.Duration {
	if s.live != nil {
		if timeout := s.live.ShutdownTimeout(); timeout > 0 {
			return timeout
		}
	}
	if s.shutdownTimeout <= 0 {
		return shutdown.DefaultTimeout
	}
	return s.shutdownTimeout
}
