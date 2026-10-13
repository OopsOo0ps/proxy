package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
)

// 本文件是验收闸门自身的负例与正例对照（设计文档 §4.2）：
// 检查逻辑拆分在 conformance.go 的 check* 函数中（返回错误列表），
// 这里直接驱动它们——故意写坏的假实现必须被拦住，闸门才可信。

// —— 假实现（负例） ——

// nilDialTransport：DialTunnel 返回 (nil, nil) 的假成功。
type nilDialTransport struct{}

func (nilDialTransport) DialTunnel(context.Context, core.Target) (net.Conn, error) { return nil, nil }

// fakeAlwaysDial：无视 ctx 恒返回可用连接（假成功）。
type fakeAlwaysDial struct{}

func (fakeAlwaysDial) DialTunnel(context.Context, core.Target) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go echoPipe(c2)
	return c1, nil
}

// fakePrewarmer：Bind 行为可注入的两阶段假实现。
type fakePrewarmer struct {
	bindFn func(ctx context.Context, p Prepared, target core.Target) (net.Conn, error)
}

func (fakePrewarmer) ConnectIdle(ctx context.Context) (Prepared, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c1, c2 := net.Pipe()
	go echoPipe(c2)
	return pipeHandle{c1, c2}, nil
}

func (f fakePrewarmer) Bind(ctx context.Context, p Prepared, target core.Target) (net.Conn, error) {
	return f.bindFn(ctx, p, target)
}

// fakeProber：探测假成功——对不可达端点也返回 nil。
type fakeProber struct{}

func (fakeProber) Probe(context.Context) error { return nil }

// —— 合法实现（正例对照，内存内无外部端口依赖） ——

// pipeHandle 是基于 net.Pipe 的合法 Prepared。
type pipeHandle struct {
	client net.Conn
	server net.Conn
}

func (p pipeHandle) Discard() {
	_ = p.client.Close()
	_ = p.server.Close()
}

func echoPipe(c net.Conn) {
	_, _ = io.Copy(c, c)
	_ = c.Close()
}

// pipeTransport：具备全部三项能力的合法内存传输。
// connect/bind 两阶段语义显式建模：Bind 在空闲连接上写出绑定标记，
// 句柄被 Discard 后写出必然失败（对应真实协议的线级行为）。
type pipeTransport struct{}

func (pipeTransport) DialTunnel(ctx context.Context, target core.Target) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c1, c2 := net.Pipe()
	go echoPipe(c2)
	return c1, nil
}

func (pipeTransport) ConnectIdle(ctx context.Context) (Prepared, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c1, c2 := net.Pipe()
	go echoPipe(c2)
	return pipeHandle{c1, c2}, nil
}

func (pipeTransport) Bind(ctx context.Context, p Prepared, target core.Target) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h, ok := p.(pipeHandle)
	if !ok {
		return nil, errors.New("pipeTransport: unexpected prepared handle")
	}
	// 绑定请求语义：写出标记并等待对端回显（内存回显服务端原样返回），
	// 句柄被 Discard 后写出/读取必然失败。
	if err := h.client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return nil, err
	}
	marker := []byte(target.String() + "\n")
	if _, err := h.client.Write(marker); err != nil {
		return nil, err
	}
	got := make([]byte, len(marker))
	if _, err := io.ReadFull(h.client, got); err != nil {
		return nil, err
	}
	if string(got) != string(marker) {
		return nil, errors.New("pipeTransport: bind marker mismatch")
	}
	_ = h.client.SetDeadline(time.Time{})
	return h.client, nil
}

// directTransport：直连回环目标的合法 Transport（走真实 TCP，覆盖半关闭检查）。
type directTransport struct{ d net.Dialer }

func (t *directTransport) DialTunnel(ctx context.Context, target core.Target) (net.Conn, error) {
	return t.d.DialContext(ctx, "tcp", target.String())
}

// —— 负例断言 ——

func testTarget(t *testing.T) core.Target {
	t.Helper()
	return startEchoTarget(t)
}

func cancelledCtx(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	return cctx
}

// TestGuardsCatchNilDial 假成功 (nil, nil) 必须被 checkDial 拦住。
func TestGuardsCatchNilDial(t *testing.T) {
	errs := checkDial(context.Background(), nilDialTransport{}, testTarget(t))
	if len(errs) == 0 {
		t.Fatal("checkDial must reject DialTunnel (nil, nil) fake success")
	}
}

// TestGuardsCatchCanceledDial 已取消 ctx 上的拨号假成功必须被拦住。
func TestGuardsCatchCanceledDial(t *testing.T) {
	errs := checkDial(cancelledCtx(context.Background()), fakeAlwaysDial{}, testTarget(t))
	if len(errs) == 0 {
		t.Fatal("checkDial must reject DialTunnel fake success with canceled ctx")
	}
}

// TestGuardsCatchNilBind Bind 假成功（返回 nil conn）必须被 checkPrewarm 拦住。
func TestGuardsCatchNilBind(t *testing.T) {
	pw := fakePrewarmer{bindFn: func(context.Context, Prepared, core.Target) (net.Conn, error) {
		return nil, nil
	}}
	errs := checkPrewarm(context.Background(), nilDialTransport{}, pw, testTarget(t))
	if len(errs) == 0 {
		t.Fatal("checkPrewarm must reject Bind (nil, nil) fake success")
	}
}

// TestGuardsCatchBindAfterDiscard 无视 Discard 的 Bind 假成功必须被拦住。
func TestGuardsCatchBindAfterDiscard(t *testing.T) {
	pw := fakePrewarmer{bindFn: func(_ context.Context, p Prepared, _ core.Target) (net.Conn, error) {
		h, ok := p.(pipeHandle)
		if !ok {
			return nil, errors.New("unexpected handle")
		}
		return h.client, nil // 不写出绑定标记：对已 Discard 的句柄返回假成功
	}}
	errs := checkPrewarm(context.Background(), nilDialTransport{}, pw, testTarget(t))
	if len(errs) == 0 {
		t.Fatal("checkPrewarm must reject Bind on a discarded handle")
	}
}

// TestGuardsCatchProbeFakeSuccess 探测假成功（已取消 ctx 仍返回 nil）必须被拦住。
func TestGuardsCatchProbeFakeSuccess(t *testing.T) {
	errs := checkProbe(context.Background(), fakeProber{})
	if len(errs) == 0 {
		t.Fatal("checkProbe must reject a probe faking success on canceled ctx")
	}
}

// —— 正例对照（闸门不误报） ——

// TestChecksPassForHonestImplementations 合法实现的检查零违例。
func TestChecksPassForHonestImplementations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), conformanceTimeout)
	defer cancel()
	target := testTarget(t)
	if errs := checkDial(ctx, &directTransport{}, target); len(errs) > 0 {
		t.Fatalf("checkDial false positive: %v", errs)
	}
	if errs := checkDial(ctx, pipeTransport{}, target); len(errs) > 0 {
		t.Fatalf("checkDial false positive: %v", errs)
	}
	if errs := checkPrewarm(ctx, pipeTransport{}, pipeTransport{}, target); len(errs) > 0 {
		t.Fatalf("checkPrewarm false positive: %v", errs)
	}
}

// TestRunConformanceAcceptsHonestTransport 完整闸门对合法传输通过。
func TestRunConformanceAcceptsHonestTransport(t *testing.T) {
	RunConformance(t, pipeTransport{})
}
