package testutil

// 本文件是入站一致性套件自身的测试（设计文档 §9.2 / §4.2 同一模式）：
// 用一个内存假入站作正例对照（全部 10 条不变量通过），再故意写坏三条
// 关键行为（拒绝路径仍拨号 / 强制断开不发终态 / 丢弃预读字节），
// 套件必须把它们拦住——闸门能拦坏实现，才可信。

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/relay"
	"github.com/OopsOo0ps/proxy/internal/session"
)

// fakeProto 是假入站的观测口径。
const fakeProto = "fake"

// fakeOptions 是假入站的行为开关：全零 = 诚实实现；置位 = 故意写坏。
type fakeOptions struct {
	badDialOnDeny bool // 负例：拒绝路径仍然拨号（C2 应拦截）
	skipConnDone  bool // 负例：强制断开后不发 ConnDone（C6 应拦截）
	dropPrefix    bool // 负例：丢弃 bufio 预读字节（C10 应拦截）
}

// fakeHandler 是最小入站的协议逻辑（session.ConnHandler）。
// 协议：首字节命令——'S' = 建立会话（经假出站转发，支持预读前置）；
// 'D' = 认证拒绝（协议合法拒绝响应）；命令后的字节属于转发载荷。
type fakeHandler struct {
	opts fakeOptions
	tel  core.Telemetry
	dial core.TargetDialer
	idle time.Duration
}

func (h *fakeHandler) ServeConn(connCtx context.Context, raw net.Conn) {
	defer func() { _ = raw.Close() }()
	h.tel.ConnOpened(fakeProto)

	br := bufio.NewReader(raw)
	cmd, err := br.ReadByte()
	if err != nil {
		h.tel.ConnRejected(fakeProto, core.ResultError)
		return
	}
	switch cmd {
	case 'D':
		if h.opts.badDialOnDeny {
			conn, _, dialErr := h.dial.DialTarget(connCtx, core.Target{Host: "fake.test", Port: 1})
			if dialErr == nil {
				_ = conn.Close()
			}
		}
		h.tel.ConnRejected(fakeProto, core.ResultDenied)
		_, _ = raw.Write([]byte("DENIED\n"))
	case 'S':
		conn, route, err := h.dial.DialTarget(connCtx, core.Target{Host: "fake.test", Port: 1})
		if err != nil {
			h.tel.ConnDone(core.ConnAttrs{Proto: fakeProto, Route: route, Result: core.ResultDialFail})
			return
		}
		defer func() { _ = conn.Close() }()
		if _, err := raw.Write([]byte("OK\n")); err != nil {
			h.tel.ConnDone(core.ConnAttrs{Proto: fakeProto, Route: route, Result: core.ResultError})
			return
		}
		client := raw
		if !h.opts.dropPrefix {
			// 诚实实现：bufio 预读的载荷经 PrefixConn 原样前置转交（C10）。
			client = relay.PrefixConn(raw, br)
		}
		_, relayErr := relay.BiCopy(connCtx, client, conn, h.idle)
		result := core.ResultOK
		if relay.IsFailure(relayErr) {
			result = core.ResultError
		}
		if !h.opts.skipConnDone {
			h.tel.ConnDone(core.ConnAttrs{Proto: fakeProto, Route: route, Result: result})
		}
	default:
		h.tel.ConnRejected(fakeProto, core.ResultError)
	}
}

// fakeInbound 是运行中的假入站：session.Serve 提供接受/排空机械，
// 与真实入站共用同一生命周期原语，套件据此断言双 ctx 语义。
type fakeInbound struct {
	ln      net.Listener
	handler *fakeHandler
	drain   time.Duration
}

func (i *fakeInbound) Addr() string { return i.ln.Addr().String() }

func (i *fakeInbound) Serve(ctx context.Context) error {
	return session.Serve(ctx, i.ln, i.handler, session.Options{
		DrainTimeout: func() time.Duration { return i.drain },
	})
}

// gatedListener 是测试用并发闸（与 connlimit.WrapListener 语义一致；
// 套件依赖边界为 L0/L1，此处不 import connlimit）。超限连接交给 reject
// 处理后继续接受；返回的连接在 Close 时归还名额。
type gatedListener struct {
	net.Listener
	limit  int
	reject func(net.Conn)

	mu     sync.Mutex
	active int
}

func (l *gatedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.mu.Lock()
		ok := l.active < l.limit
		if ok {
			l.active++
		}
		l.mu.Unlock()
		if ok {
			return &gatedConn{Conn: conn, l: l}, nil
		}
		l.reject(conn)
	}
}

func (l *gatedListener) release() {
	l.mu.Lock()
	if l.active > 0 {
		l.active--
	}
	l.mu.Unlock()
}

type gatedConn struct {
	net.Conn
	l    *gatedListener
	once sync.Once
}

func (c *gatedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.l.release)
	return err
}

// fakeFixture 返回假入站夹具：握手 = 单字节命令 + 可选预读载荷，
// 会话建立后被测侧回写 "OK\n" 确认。
func fakeFixture(opts *fakeOptions) InboundFixture {
	return InboundFixture{
		New: func(t *testing.T, f InboundFixture) Inbound {
			t.Helper()
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("fake inbound listen: %v", err)
			}
			if f.ConnLimit > 0 {
				ln = &gatedListener{Listener: ln, limit: f.ConnLimit, reject: func(conn net.Conn) {
					// 与组装根的接线一致：过载拒绝也是一次 accept 后的终态。
					f.Tel.ConnOpened(fakeProto)
					f.Tel.ConnRejected(fakeProto, core.ResultOverload)
					_ = conn.Close()
				}}
			}
			return &fakeInbound{
				ln:      ln,
				drain:   f.Drain,
				handler: &fakeHandler{opts: *opts, tel: f.Tel, dial: f.Dial, idle: f.Idle},
			}
		},
		Request: func(t *testing.T, addr string, f InboundFixture) (net.Conn, error) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			_ = conn.SetDeadline(time.Now().Add(suiteOpTimeout))
			burst := []byte{'S'}
			burst = append(burst, f.Preloaded...)
			if _, err := conn.Write(burst); err != nil {
				_ = conn.Close()
				return nil, err
			}
			var ack [3]byte // "OK\n"
			if _, err := io.ReadFull(conn, ack[:]); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("read session ack: %w", err)
			}
			if string(ack[:]) != "OK\n" {
				_ = conn.Close()
				return nil, fmt.Errorf("session ack = %q, want %q", ack, "OK\n")
			}
			_ = conn.SetDeadline(time.Time{})
			return conn, nil
		},
		Deny: func(t *testing.T, addr string) error {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(suiteOpTimeout))
			if _, err := conn.Write([]byte{'D'}); err != nil {
				return err
			}
			var reply [7]byte // "DENIED\n"
			if _, err := io.ReadFull(conn, reply[:]); err != nil {
				return err
			}
			if string(reply[:]) != "DENIED\n" {
				return fmt.Errorf("rejection = %q, want %q", reply, "DENIED\\n")
			}
			return errors.New("fake: denied")
		},
		Overload: func(t *testing.T, addr string) error {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(suiteOpTimeout))
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return err
			}
			// 闸拒绝后连接被直接关闭（无会话确认）：读应得到 EOF。
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				return errors.New("fake: overloaded session unexpectedly served")
			}
			return errors.New("fake: overloaded")
		},
		Preloaded: []byte("fake-preloaded-payload"),
		Idle:      suiteIdleTimeout,
		Drain:     suiteDrain,
		Proto:     fakeProto,
	}
}

// TestRunInboundConformanceAcceptsHonestInbound 正例对照：诚实实现通过
// 全部 10 条不变量。
func TestRunInboundConformanceAcceptsHonestInbound(t *testing.T) {
	RunInboundConformance(t, fakeFixture(&fakeOptions{}))
}

// TestSuiteCatchesDenyDialing 负例：认证失败的拒绝路径仍然拨号，
// C2 的零拨号断言必须拦截。
func TestSuiteCatchesDenyDialing(t *testing.T) {
	errs := checkAuthDenial(t, fakeFixture(&fakeOptions{badDialOnDeny: true}))
	if len(errs) == 0 {
		t.Fatal("denial path that dials must be caught by C2 (zero dial)")
	}
}

// TestSuiteCatchesMissingConnDoneOnForceClose 负例：排空期限到点被强制
// 断开后不发 ConnDone，C6 的终态断言必须拦截（active 计数会泄漏）。
func TestSuiteCatchesMissingConnDoneOnForceClose(t *testing.T) {
	errs := checkForceCloseReportsDone(t, fakeFixture(&fakeOptions{skipConnDone: true}))
	if len(errs) == 0 {
		t.Fatal("force close without ConnDone must be caught by C6")
	}
}

// TestSuiteCatchesDroppedPreloadedBytes 负例：握手期预读的字节被丢弃，
// C10 的原样转交断言必须拦截。
func TestSuiteCatchesDroppedPreloadedBytes(t *testing.T) {
	errs := checkPreloadedForwarding(t, fakeFixture(&fakeOptions{dropPrefix: true}))
	if len(errs) == 0 {
		t.Fatal("dropped preloaded bytes must be caught by C10")
	}
}
