package socks5_test

// 入站一致性套件接入（设计文档 §9.2 / §12：SOCKS5 入站走 C1–C10）。
// 本文件只提供协议侧夹具：被测入站的构造（与组装根的接线一致：connlimit
// 过载闸 + 拒绝遥测）与 SOCKS5 客户端驱动；契约断言全部来自套件。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/socks5"
	"github.com/OopsOo0ps/proxy/internal/sockswire"
	"github.com/OopsOo0ps/proxy/internal/testutil"
)

// conformanceUser / conformancePass 是夹具入站的合法凭据；
// conformanceTarget 是 CONNECT 的目标（假出站忽略目标、拨到套件回显上游）。
const (
	conformanceUser   = "conformance"
	conformancePass   = "conformance-secret"
	conformanceTarget = "conformance.test"
	// conformancePort 是目标端口（假出站忽略目标，任意合法值即可）。
	conformancePort = 443
)

// TestInboundConformance 跑 SOCKS5 入站的全部 10 条不变量。
func TestInboundConformance(t *testing.T) {
	testutil.RunInboundConformance(t, testutil.InboundFixture{
		New:      newConformanceInbound,
		Request:  conformanceRequest,
		Deny:     conformanceDeny,
		Overload: conformanceOverload,
		// 握手期捎带的载荷（模拟客户端把请求与首批数据连发）。
		Preloaded: []byte("socks5-preloaded-payload-after-request"),
		Idle:      1500 * time.Millisecond,
		Drain:     600 * time.Millisecond,
		Proto:     core.ProtoSOCKS5,
	})
}

// newConformanceInbound 构造被测 SOCKS5 入站：认证开启（C2 需要），监听
// 回环，connlimit 过载闸与组装根同接线（先开后拒，拒绝遥测在闭包内发射）。
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
		f.Tel.ConnOpened(core.ProtoSOCKS5)
		f.Tel.ConnRejected(core.ProtoSOCKS5, core.ResultOverload)
		socks5.WriteOverloadReply(conn)
	})
	srv := &socks5.Server{
		Auth:             store,
		Dialer:           f.Dial,
		Logger:           nil,
		Telemetry:        f.Tel,
		HandshakeTimeout: 5 * time.Second,
		IdleTimeout:      f.Idle,
		ShutdownTimeout:  f.Drain,
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

// socks5Handshake 完成一次 SOCKS5 客户端交换：问候 + 用户名密码认证 +
// CONNECT 请求（payload 非空时随请求一并发出，捎带给握手期的 bufio）。
// 返回隧道 conn；失败时返回错误（明确失败响应的客户端侧观测）。
func socks5Handshake(conn net.Conn, username, password string, payload []byte) (net.Conn, error) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 问候：用户名密码方式（夹具入站开启认证）。
	if _, err := conn.Write([]byte{socks5.Version, 1, socks5.MethodUserPass}); err != nil {
		return nil, err
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		return nil, err
	}
	if sel[0] != socks5.Version {
		return nil, fmt.Errorf("method selection version = %#x", sel[0])
	}
	switch sel[1] {
	case socks5.MethodUserPass:
		// 继续认证子协商。
	case socks5.MethodNoAcceptable:
		return nil, errors.New("socks5: no acceptable method (overload or policy rejection)")
	default:
		return nil, fmt.Errorf("unexpected method %#x", sel[1])
	}

	authReq := []byte{socks5.UserPassVersion, byte(len(username))}
	authReq = append(authReq, username...)
	authReq = append(authReq, byte(len(password)))
	authReq = append(authReq, password...)
	if _, err := conn.Write(authReq); err != nil {
		return nil, err
	}
	var authResp [2]byte
	if _, err := io.ReadFull(conn, authResp[:]); err != nil {
		return nil, err
	}
	if authResp[0] != socks5.UserPassVersion {
		return nil, fmt.Errorf("auth version = %#x", authResp[0])
	}
	if authResp[1] != socks5.UserPassStatusOK {
		return nil, errors.New("socks5: authentication failed")
	}

	addr, err := sockswire.EncodeAddr(conformanceTarget, conformancePort)
	if err != nil {
		return nil, err
	}
	req := append([]byte{socks5.Version, socks5.CmdConnect, 0x00}, addr...)
	req = append(req, payload...) // 捎带载荷与请求同一次写出
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	var head [4]byte // VER, REP, RSV, ATYP
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, err
	}
	if head[0] != socks5.Version {
		return nil, fmt.Errorf("reply version = %#x", head[0])
	}
	if head[1] != socks5.ReplySuccess {
		return nil, fmt.Errorf("reply = %#x", head[1])
	}
	switch head[3] {
	case socks5.ATYPIPv4:
		var rest [6]byte
		if _, err := io.ReadFull(conn, rest[:]); err != nil {
			return nil, err
		}
	case socks5.ATYPIPv6:
		var rest [18]byte
		if _, err := io.ReadFull(conn, rest[:]); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unexpected reply atyp %#x", head[3])
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// conformanceRequest 完成握手（含认证），返回客户端侧隧道 conn。
func conformanceRequest(t *testing.T, addr string, f testutil.InboundFixture) (net.Conn, error) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	tunnel, err := socks5Handshake(conn, conformanceUser, conformancePass, f.Preloaded)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tunnel, nil
}

// conformanceDeny 发起一次凭据错误的会话：认证子协商回失败状态 = 协议
// 合法拒绝响应。
func conformanceDeny(t *testing.T, addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := socks5Handshake(conn, conformanceUser, "wrong-password", nil); err == nil {
		return errors.New("wrong credentials unexpectedly accepted")
	}
	return errors.New("socks5: denied")
}

// conformanceOverload 在闸关闭时发起会话：0x05 0xFF（无可用认证方式）=
// RFC 1928 认证前唯一协议合法的过载回复。
func conformanceOverload(t *testing.T, addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := socks5Handshake(conn, conformanceUser, conformancePass, nil); err == nil {
		return errors.New("overloaded session unexpectedly established")
	}
	return errors.New("socks5: overloaded")
}
