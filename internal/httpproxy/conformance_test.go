package httpproxy_test

// 入站一致性套件接入（设计文档 §9.2 / §12：HTTP/HTTPS 入站走 C1–C10）。
// 本文件只提供协议侧夹具：被测入站的构造（与组装根的接线一致：connlimit
// 过载闸 + 拒绝遥测）与 HTTP 代理客户端驱动；契约断言全部来自套件。

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/httpproxy"
	"github.com/OopsOo0ps/proxy/internal/relay"
	"github.com/OopsOo0ps/proxy/internal/testutil"
)

// conformanceUser / conformancePass 是夹具入站的合法凭据；
// conformanceTarget 是 CONNECT 的目标（假出站忽略目标、拨到套件回显上游）。
const (
	conformanceUser   = "conformance"
	conformancePass   = "conformance-secret"
	conformanceTarget = "conformance.test:443"
)

var (
	// conformanceAuth 是合法凭据的 Proxy-Authorization 头。
	conformanceAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(conformanceUser+":"+conformancePass))
	// conformanceBad 是错误凭据的 Proxy-Authorization 头（认证失败路径）。
	conformanceBad = "Basic " + base64.StdEncoding.EncodeToString([]byte(conformanceUser+":wrong"))
)

// TestInboundConformance 跑 HTTP 代理入站的全部 10 条不变量。
func TestInboundConformance(t *testing.T) {
	testutil.RunInboundConformance(t, testutil.InboundFixture{
		New:      newConformanceInbound,
		Request:  conformanceRequest,
		Deny:     conformanceDeny,
		Overload: conformanceOverload,
		// 握手期捎带的载荷（模拟 TLS ClientHello 的首记录）。
		Preloaded: []byte("httpproxy-preloaded-clienthello-payload"),
		Idle:      1500 * time.Millisecond,
		Drain:     600 * time.Millisecond,
		Proto:     core.ProtoHTTP,
	})
}

// newConformanceInbound 构造被测 HTTP 入站：认证开启（C2 需要），监听回环，
// connlimit 过载闸与组装根同接线（先开后拒，拒绝遥测在闭包内发射）。
func newConformanceInbound(t *testing.T, f testutil.InboundFixture) testutil.Inbound {
	t.Helper()
	store, err := auth.NewStore([]auth.User{{Username: conformanceUser, Password: conformancePass}})
	if err != nil {
		t.Fatalf("auth store: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var limiter *connlimit.Limiter
	if f.ConnLimit > 0 {
		limiter = connlimit.New(f.ConnLimit)
	}
	wrapped := connlimit.WrapListener(ln, limiter, func(conn net.Conn) {
		// 与组装根一致：过载拒绝也是一次 accept 后的终态（active 口径平衡）。
		f.Tel.ConnOpened(core.ProtoHTTP)
		f.Tel.ConnRejected(core.ProtoHTTP, core.ResultOverload)
		httpproxy.WriteOverloaded(conn)
	})
	srv := &httpproxy.Server{
		Auth:              store,
		Dialer:            f.Dial,
		Logger:            nil,
		Telemetry:         f.Tel,
		IdleTimeout:       f.Idle,
		ReadHeaderTimeout: 5 * time.Second,
		ShutdownTimeout:   f.Drain,
	}
	return startedServer{
		addr:  wrapped.Addr().String(),
		serve: func(ctx context.Context) error { return srv.Serve(ctx, wrapped) },
	}
}

// startedServer 是构造产物到 testutil.Inbound 的适配。
type startedServer struct {
	addr  string
	serve func(ctx context.Context) error
}

func (s startedServer) Addr() string                    { return s.addr }
func (s startedServer) Serve(ctx context.Context) error { return s.serve(ctx) }

// conformanceRequest 发起一次带认证的 CONNECT（f.Preloaded 非空时随请求
// 一并发出），返回客户端侧隧道 conn；非 200 响应 = 明确失败响应。
func conformanceRequest(t *testing.T, addr string, f testutil.InboundFixture) (net.Conn, error) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)

	req := "CONNECT " + conformanceTarget + " HTTP/1.1\r\n" +
		"Host: " + conformanceTarget + "\r\n" +
		"Proxy-Authorization: " + conformanceAuth + "\r\n\r\n"
	if len(f.Preloaded) > 0 {
		req += string(f.Preloaded) // 与 CONNECT 同一次写出：捎带载荷
	}
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT rejected: status %d", resp.StatusCode)
	}
	_ = conn.SetDeadline(time.Time{})
	// 客户端侧的 bufio 可能已预读捎带载荷：经 PrefixConn 原样保留。
	return relay.PrefixConn(conn, br), nil
}

// conformanceDeny 发起一次凭据错误的 CONNECT：407 = 协议合法拒绝响应。
func conformanceDeny(t *testing.T, addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := "CONNECT " + conformanceTarget + " HTTP/1.1\r\n" +
		"Host: " + conformanceTarget + "\r\n" +
		"Proxy-Authorization: " + conformanceBad + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		return fmt.Errorf("status = %d, want 407", resp.StatusCode)
	}
	return errors.New("http: denied (407)")
}

// conformanceOverload 在闸关闭时发起会话：503 = 协议过载拒绝响应。
func conformanceOverload(t *testing.T, addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := "CONNECT " + conformanceTarget + " HTTP/1.1\r\n" +
		"Host: " + conformanceTarget + "\r\n" +
		"Proxy-Authorization: " + conformanceAuth + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		return fmt.Errorf("status = %d, want 503", resp.StatusCode)
	}
	return errors.New("http: overloaded (503)")
}
