// 入站一致性套件（设计文档 §9.2，10 条不变量 C1–C10）。
//
// 入站的「协议方言」无法统一（HTTP 407 与 SOCKS5 拒绝码天然不同），但契约
// 断言可以统一：套件接收各协议外部测试提供的 InboundFixture（协议客户端
// 驱动——它本来就是该协议测试需要写的代码），在回环夹具上统一断言拒绝、
// 遥测与生命周期契约。检查逻辑拆分为可独立调用的 check* 函数（返回错误
// 列表），供套件自身的负例测试直接驱动——故意写坏的入站实现必须被拦住，
// 套件才可信（与 outbound.RunConformance 同一模式）。
//
// 遥测事件序列用记录器假件直接断言（§8.4 测试纪律：组件层可见，不靠
// e2e /metrics 文本兜底）；假出站记录拨号次数（C2 零拨号）并返回可控的
// 权威路径（C4 标签一致性）。
//
// 依赖边界：本文件只依赖 L0/L1（core）与标准库，不 import 协议包、
// 不 import metrics。
package testutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
)

// Inbound 是套件对被测入站的最小要求：已绑定监听、可启动服务。
type Inbound interface {
	// Addr 返回监听地址（Request / Deny / Overload 的连接目标）。
	Addr() string
	// Serve 阻塞服务直到 ctx 取消；取消后按入站自身的排空语义收尾
	//（排空期限由 Fixture.Drain 在构造时注入）。
	Serve(ctx context.Context) error
}

// InboundFixture 是协议侧提供的入站夹具（每个协议的外部测试各一份）。
//
// 与 §9.2 原文形状的唯一扩充是套件注入面：Tel（记录器假件）、Dial（假出站）
// 由套件在每次子测试中注入，New 构造被测入站时必须接线；ConnLimit 供 C8
// 打开并发闸；Proto 是观测口径（core.Proto*）。Request 相比原文带回握手
// 错误——C3 需要断言「明确失败响应」表现为客户端可感知的失败。
type InboundFixture struct {
	// New 构造被测入站（每次子测试重新构造）：监听回环地址、把 f.Tel 接进
	// 遥测出口、f.Dial 接进目标拨号器、f.Idle / f.Drain 接进空闲与排空期限；
	// f.ConnLimit > 0 时以该上限包装监听（过载拒绝响应与拒绝遥测由夹具按
	// 组装根的接线方式提供）。返回的入站尚未启动（套件负责 Serve）。
	New func(t *testing.T, f InboundFixture) Inbound
	// Request 完成协议握手（含认证），返回客户端侧隧道 conn。
	// f.Preloaded 非空时必须随请求一并发出（供 C10 断言原样转交）。
	// 出站建立失败时必须返回非 nil error（协议明确失败响应的客户端侧观测）。
	Request func(t *testing.T, addr string, f InboundFixture) (net.Conn, error)
	// Deny 发起一次必被拒的会话（认证失败）。返回客户端观测到的错误；
	// nil 表示会话意外成功（套件判为违例）。
	Deny func(t *testing.T, addr string) error
	// Overload 在闸关闭时发起会话。返回客户端观测到的错误；
	// nil 函数 = 该协议无拒绝通道（套件断言连接被直接关闭）。
	Overload func(t *testing.T, addr string) error
	// Preloaded 是握手期随请求一并发出的载荷（C10：预读字节必须原样前置
	// 转交；空切片判为夹具缺省，C10 直接失败）。
	Preloaded []byte
	// Idle / Drain 是测试可缩短的空闲回收与关停排空期限（构造时注入被测
	// 入站；Drain 必须小于 Idle，C6 的强制断开才先于空闲回收发生）。
	Idle, Drain time.Duration
	// Proto 是被测入站的观测口径（core.Proto*），遥测词汇断言使用。
	Proto string

	// —— 以下字段由套件注入，夹具不得改写 ——

	// Tel 是套件的遥测记录器假件。
	Tel core.Telemetry
	// Dial 是套件的假出站（记录拨号次数、可控失败与权威路径）。
	Dial core.TargetDialer
	// ConnLimit 是并发闸上限；0 = 不限流（仅 C8 设为 1）。
	ConnLimit int
}

// 套件内各网络操作的期限（回环夹具，远小于 CI 超时）。
const (
	suiteOpTimeout   = 5 * time.Second
	suiteEventWait   = 3 * time.Second
	suiteIdleTimeout = 1500 * time.Millisecond
	suiteDrain       = 600 * time.Millisecond
)

// RunInboundConformance 对被测入站跑 C1–C10（每条一个子测试，入站按子测试
// 重新构造）。不变量与线上故障的对应关系见设计文档 §9.2：
//
//	C1 会话能双向转发字节（半关闭、收尾正确）
//	C2 认证失败：协议合法拒绝响应 + 零拨号 + 遥测 ConnRejected(denied)
//	C3 拨号失败：明确失败响应 + 遥测 ConnDone(result=dial_fail)
//	C4 成功会话：遥测 result=ok 且 Route 与 DialTarget 返回的权威路径一致
//	C5 关停时存量会话在排空期内正常完成（不被打断）
//	C6 排空期限到点后阻塞的连接被强制断开，且仍发 ConnDone
//	C7 关停后不再接受新连接
//	C8 超过并发上限：按协议回过载拒绝，遥测 ConnRejected(overloaded)
//	C9 空闲超过期限的会话被回收
//	C10 握手期预读的字节被原样前置转交
func RunInboundConformance(t *testing.T, f InboundFixture) {
	t.Helper()
	switch {
	case f.New == nil:
		t.Fatal("inbound conformance: fixture must provide New")
	case f.Request == nil:
		t.Fatal("inbound conformance: fixture must provide Request")
	case f.Deny == nil:
		t.Fatal("inbound conformance: fixture must provide Deny")
	case f.Proto == "":
		t.Fatal("inbound conformance: fixture must declare Proto (core.Proto*)")
	case f.Drain <= 0 || f.Idle <= f.Drain:
		t.Fatal("inbound conformance: fixture must set Drain > 0 and Idle > Drain (C6 force close must beat idle reclaim)")
	}
	checks := []struct {
		name string
		run  func(t *testing.T, f InboundFixture) []error
	}{
		{"C1 relay both directions with half close", checkRelay},
		{"C2 auth denial without dialing", checkAuthDenial},
		{"C3 dial failure reported", checkDialFailure},
		{"C4 authoritative route in telemetry", checkRouteAuthority},
		{"C5 drain completes in-flight sessions", checkDrainCompletes},
		{"C6 force close still reports ConnDone", checkForceCloseReportsDone},
		{"C7 no new connections after shutdown", checkNoAcceptAfterShutdown},
		{"C8 overload rejected via protocol", checkOverload},
		{"C9 idle sessions reclaimed", checkIdleReclaim},
		{"C10 preloaded bytes forwarded", checkPreloadedForwarding},
	}
	for _, c := range checks {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Helper()
			if errs := c.run(t, f); len(errs) > 0 {
				t.Errorf("%s failed:\n%s", c.name, joinErrors(errs))
			}
		})
	}
}

// —— 检查函数（返回违例列表；套件自身的负例测试直接驱动它们）——

// checkRelay 验证 C1：会话能双向转发字节，半关闭把 EOF 传递到对侧并正确收尾
// （遥测恰好一条 ConnDone(result=ok)）。
func checkRelay(t *testing.T, f InboundFixture) []error {
	run := startInbound(t, f)
	conn, err := requestSession(t, run)
	if err != nil {
		return []error{fmt.Errorf("request: %w", err)}
	}
	defer func() { _ = conn.Close() }()

	const payload = "conformance-c1-payload"
	if err := conn.SetDeadline(time.Now().Add(suiteOpTimeout)); err != nil {
		return []error{err}
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		return []error{fmt.Errorf("write upstream: %w", err)}
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return []error{fmt.Errorf("read echo: %w", err)}
	}
	if string(got) != payload {
		return []error{fmt.Errorf("echo = %q, want %q", got, payload)}
	}
	// 半关闭：客户端写方向 EOF 应传播到对端并让会话收尾（读到 EOF）。
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			return []error{fmt.Errorf("half close: %w", err)}
		}
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		return []error{errors.New("expected EOF after half close")}
	}

	opened, rejected, done := waitDone(t, run.tel, 1)
	var errs []error
	if len(opened) != 1 {
		errs = append(errs, fmt.Errorf("ConnOpened ×%d, want 1", len(opened)))
	}
	if len(rejected) != 0 {
		errs = append(errs, fmt.Errorf("ConnRejected = %v, want none", rejected))
	}
	if len(done) != 1 {
		return append(errs, fmt.Errorf("ConnDone ×%d, want exactly 1", len(done)))
	}
	if done[0].Result != core.ResultOK {
		errs = append(errs, fmt.Errorf("ConnDone result = %q, want %q", done[0].Result, core.ResultOK))
	}
	if done[0].Proto != f.Proto {
		errs = append(errs, fmt.Errorf("ConnDone proto = %q, want %q", done[0].Proto, f.Proto))
	}
	return errs
}

// checkAuthDenial 验证 C2：认证失败 = 协议合法拒绝响应（Deny 返回错误）+
// 零拨号 + 遥测 ConnRejected(denied)（未进入服务即被拒，无 ConnDone）。
func checkAuthDenial(t *testing.T, f InboundFixture) []error {
	run := startInbound(t, f)
	if err := run.fixture.Deny(t, run.inb.Addr()); err == nil {
		return []error{errors.New("denied session must be rejected via the protocol (client observed an error)")}
	}
	if got := run.dial.count(); got != 0 {
		return []error{fmt.Errorf("dials after denial = %d, want 0（认证失败不得拨号）", got)}
	}
	var errs []error
	opened, rejected, done := waitRejection(t, run.tel)
	if len(opened) != 1 {
		errs = append(errs, fmt.Errorf("ConnOpened ×%d, want 1", len(opened)))
	}
	if len(rejected) != 1 || rejected[0] != f.Proto+"/"+core.ResultDenied {
		errs = append(errs, fmt.Errorf("ConnRejected = %v, want [%s/%s]", rejected, f.Proto, core.ResultDenied))
	}
	if len(done) != 0 {
		errs = append(errs, fmt.Errorf("ConnDone = %+v, want none（认证失败无路由维度）", done))
	}
	return errs
}

// checkDialFailure 验证 C3：拨号失败 = 客户端看到明确失败响应（Request 返回
// 错误）+ 恰好一次拨号 + 遥测 ConnDone(result=dial_fail)。
func checkDialFailure(t *testing.T, f InboundFixture) []error {
	run := startInbound(t, f)
	run.dial.setErr(errors.New("stub: exit node down"))
	defer run.dial.setErr(nil)

	conn, err := run.fixture.Request(t, run.inb.Addr(), run.fixture)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		return []error{errors.New("dial failure must surface as an explicit protocol failure")}
	}
	if got := run.dial.count(); got != 1 {
		return []error{fmt.Errorf("dials = %d, want 1", got)}
	}
	_, _, done := waitDone(t, run.tel, 1)
	if len(done) != 1 {
		return []error{fmt.Errorf("ConnDone ×%d, want exactly 1", len(done))}
	}
	if done[0].Result != core.ResultDialFail {
		return []error{fmt.Errorf("ConnDone result = %q, want %q", done[0].Result, core.ResultDialFail)}
	}
	return nil
}

// checkRouteAuthority 验证 C4：成功会话的遥测 result=ok，且 Route 与
// DialTarget 返回的权威路径一致（入站不得自行推断上游，不变量 6）。
func checkRouteAuthority(t *testing.T, f InboundFixture) []error {
	run := startInbound(t, f)
	conn, err := requestSession(t, run)
	if err != nil {
		return []error{fmt.Errorf("request: %w", err)}
	}
	defer func() { _ = conn.Close() }()
	const payload = "conformance-c4"
	if err := roundTrip(conn, payload); err != nil {
		return []error{err}
	}
	_ = conn.Close()

	_, _, done := waitDone(t, run.tel, 1)
	if len(done) != 1 {
		return []error{fmt.Errorf("ConnDone ×%d, want exactly 1", len(done))}
	}
	if done[0].Result != core.ResultOK {
		return []error{fmt.Errorf("ConnDone result = %q, want %q", done[0].Result, core.ResultOK)}
	}
	want := run.dial.currentRoute()
	if done[0].Route != want {
		return []error{fmt.Errorf("ConnDone route = %+v, want the authoritative %+v from DialTarget", done[0].Route, want)}
	}
	return nil
}

// checkDrainCompletes 验证 C5：关停（停止接受）后，存量会话在排空期内
// 正常完成，不被打断。
func checkDrainCompletes(t *testing.T, f InboundFixture) []error {
	run := startInbound(t, f)
	conn, err := requestSession(t, run)
	if err != nil {
		return []error{fmt.Errorf("request: %w", err)}
	}
	defer func() { _ = conn.Close() }()

	// 关停：停止接受新连接，存量进入排空（期限 = f.Drain）。
	run.cancel()

	const payload = "conformance-c5-drain"
	if err := conn.SetDeadline(time.Now().Add(suiteOpTimeout)); err != nil {
		return []error{err}
	}
	if err := roundTrip(conn, payload); err != nil {
		return []error{fmt.Errorf("session must complete within the drain window: %w", err)}
	}
	_ = conn.Close()

	if err := run.serveError(); err != nil {
		return []error{fmt.Errorf("Serve after drain: %w", err)}
	}
	_, _, done := waitDone(t, run.tel, 1)
	if len(done) != 1 || done[0].Result != core.ResultOK {
		return []error{fmt.Errorf("ConnDone = %+v, want exactly 1 with result=ok", done)}
	}
	return nil
}

// checkForceCloseReportsDone 验证 C6：排空期限到点后阻塞的连接被强制断开
// （客户端读到关闭），且仍发 ConnDone（active 计数不泄漏）。
func checkForceCloseReportsDone(t *testing.T, f InboundFixture) []error {
	run := startInbound(t, f)
	conn, err := requestSession(t, run)
	if err != nil {
		return []error{fmt.Errorf("request: %w", err)}
	}
	defer func() { _ = conn.Close() }()

	run.cancel()
	// 强制断开应发生在排空期限（f.Drain）附近；客户端侧读到关闭即证据。
	_ = conn.SetReadDeadline(time.Now().Add(f.Drain + suiteOpTimeout))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		return []error{errors.New("connection should be force closed after the drain deadline")}
	}
	_, _, done := waitDone(t, run.tel, 1)
	if len(done) != 1 {
		return []error{fmt.Errorf("ConnDone ×%d, want exactly 1（强制断开后仍发终态事件）", len(done))}
	}
	if done[0].Result != core.ResultOK {
		return []error{fmt.Errorf("ConnDone result = %q, want %q（强制断开按正常收尾计）", done[0].Result, core.ResultOK)}
	}
	return nil
}

// checkNoAcceptAfterShutdown 验证 C7：关停后不再接受新连接
// （监听关闭，拨号被拒绝）。
func checkNoAcceptAfterShutdown(t *testing.T, f InboundFixture) []error {
	run := startInbound(t, f)
	run.cancel()
	if err := run.serveError(); err != nil {
		return []error{fmt.Errorf("Serve after shutdown: %w", err)}
	}
	deadline := time.Now().Add(suiteOpTimeout)
	for {
		conn, err := net.DialTimeout("tcp", run.inb.Addr(), 500*time.Millisecond)
		if err != nil {
			return nil // 监听已关闭：新连接被拒绝
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			return []error{errors.New("listener still accepts new connections after shutdown")}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// checkOverload 验证 C8：闸关闭时新会话按协议回过载拒绝（Overload 返回
// 错误），遥测 ConnRejected(overloaded)，且被拒连接不触发拨号。
// Overload 为 nil 的协议没有拒绝通道：套件断言连接被直接关闭。
func checkOverload(t *testing.T, f InboundFixture) []error {
	sub := f
	sub.ConnLimit = 1 // 闸容量 1：Request 占满后，下一条连接必被拒
	run := startInbound(t, sub)
	conn, err := requestSession(t, run)
	if err != nil {
		return []error{fmt.Errorf("first session must pass the gate: %w", err)}
	}
	defer func() { _ = conn.Close() }()

	if run.fixture.Overload == nil {
		extra, err := net.DialTimeout("tcp", run.inb.Addr(), suiteOpTimeout)
		if err != nil {
			return []error{fmt.Errorf("overload without reject channel: dial: %w", err)}
		}
		defer func() { _ = extra.Close() }()
		_ = extra.SetReadDeadline(time.Now().Add(suiteOpTimeout))
		if _, err := extra.Read(make([]byte, 1)); err == nil {
			return []error{errors.New("overloaded connection should be closed directly when no reject channel exists")}
		}
		return nil
	}

	if err := run.fixture.Overload(t, run.inb.Addr()); err == nil {
		return []error{errors.New("overloaded session must be rejected via the protocol (client observed an error)")}
	}
	var errs []error
	_, rejected, _ := waitRejection(t, run.tel)
	if !contains(rejected, f.Proto+"/"+core.ResultOverload) {
		errs = append(errs, fmt.Errorf("ConnRejected = %v, want %s/%s", rejected, f.Proto, core.ResultOverload))
	}
	if got := run.dial.count(); got != 1 {
		errs = append(errs, fmt.Errorf("dials = %d, want 1（被拒连接不得触发拨号）", got))
	}
	return errs
}

// checkIdleReclaim 验证 C9：空闲超过期限的会话被回收（连接关闭并发出终态）。
func checkIdleReclaim(t *testing.T, f InboundFixture) []error {
	run := startInbound(t, f)
	conn, err := requestSession(t, run)
	if err != nil {
		return []error{fmt.Errorf("request: %w", err)}
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(f.Idle + suiteOpTimeout))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		return []error{fmt.Errorf("idle session should be reclaimed after %s", f.Idle)}
	}
	_, _, done := waitDone(t, run.tel, 1)
	if len(done) != 1 {
		return []error{fmt.Errorf("ConnDone ×%d, want exactly 1 after idle reclaim", len(done))}
	}
	if done[0].Result != core.ResultOK {
		return []error{fmt.Errorf("ConnDone result = %q, want %q（空闲回收按正常收尾计）", done[0].Result, core.ResultOK)}
	}
	return nil
}

// checkPreloadedForwarding 验证 C10：握手期预读的字节被原样前置转交
// （bufio 读请求时捎带的载荷不丢，作为隧道的首批字节到达上游）。
func checkPreloadedForwarding(t *testing.T, f InboundFixture) []error {
	if len(f.Preloaded) == 0 {
		return []error{errors.New("fixture must set Preloaded（C10 需要握手期捎带的载荷）")}
	}
	run := startInbound(t, f)
	conn, err := run.fixture.Request(t, run.inb.Addr(), run.fixture)
	if err != nil {
		return []error{fmt.Errorf("request: %w", err)}
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(suiteOpTimeout)); err != nil {
		return []error{err}
	}
	got := make([]byte, len(f.Preloaded))
	if _, err := io.ReadFull(conn, got); err != nil {
		return []error{fmt.Errorf("read forwarded preload: %w（预读字节必须原样到达上游并被回显）", err)}
	}
	if string(got) != string(f.Preloaded) {
		return []error{fmt.Errorf("forwarded preload = %q, want %q", got, f.Preloaded)}
	}
	return nil
}

// —— 套件内部机制 ——

// runningInbound 是一次检查中被启动的被测入站及其注入产物。
type runningInbound struct {
	fixture InboundFixture
	inb     Inbound
	dial    *stubDialer
	tel     *telemetryRecorder
	cancel  context.CancelFunc
	// done 在 Serve 返回后关闭；serveErr 保存其返回值（检查与清理都
	// 可能等待，故用关闭信号 + 一次性读取，而非带缓冲的结果通道）。
	done     chan struct{}
	errMu    sync.Mutex
	serveErr error
}

// serveError 返回 Serve 的返回值（Serve 未返回时阻塞到 suiteOpTimeout）。
func (r *runningInbound) serveError() error {
	select {
	case <-r.done:
	case <-time.After(suiteOpTimeout):
		return errors.New("Serve did not stop after ctx cancel")
	}
	r.errMu.Lock()
	defer r.errMu.Unlock()
	return r.serveErr
}

// startInbound 构造并启动被测入站：注入记录器假件与假出站（回环回显上游），
// 后台 Serve，测试结束时取消并等待退出。
func startInbound(t *testing.T, f InboundFixture) *runningInbound {
	t.Helper()
	sub := f
	sub.Tel = &telemetryRecorder{}
	sub.Dial = newStubDialer(startEchoServer(t))

	inb := sub.New(t, sub)
	ctx, cancel := context.WithCancel(context.Background())
	run := &runningInbound{
		fixture: sub,
		inb:     inb,
		dial:    sub.Dial.(*stubDialer),
		tel:     sub.Tel.(*telemetryRecorder),
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	go func() {
		err := inb.Serve(ctx)
		run.errMu.Lock()
		run.serveErr = err
		run.errMu.Unlock()
		close(run.done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-run.done:
		case <-time.After(suiteOpTimeout):
			t.Error("Serve did not stop after ctx cancel")
			return
		}
		if err := run.serveError(); err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})
	return run
}

// requestSession 完成一次请求会话：Request 后消费捎带载荷的回显
// （Request 携带 f.Preloaded，回显上游会把它原样送回——这正是 C10 断言的
// 转交路径；其余检查消费掉它，从干净状态开始）。
func requestSession(t *testing.T, run *runningInbound) (net.Conn, error) {
	t.Helper()
	conn, err := run.fixture.Request(t, run.inb.Addr(), run.fixture)
	if err != nil {
		return nil, err
	}
	if err := drainPreloaded(conn, run.fixture.Preloaded); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// drainPreloaded 读回并校验捎带载荷的回显，随后清除读期限。
func drainPreloaded(conn net.Conn, preloaded []byte) error {
	if len(preloaded) == 0 {
		return nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(suiteOpTimeout))
	got := make([]byte, len(preloaded))
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("consume preloaded echo: %w", err)
	}
	if string(got) != string(preloaded) {
		return fmt.Errorf("preloaded echo = %q, want %q", got, preloaded)
	}
	return conn.SetReadDeadline(time.Time{})
}

// stubDialer 是套件注入被测入站的假出站：记录拨号次数、可注入失败、
// 返回可控的权威路径；缺省拨到套件自建的回环回显上游。
type stubDialer struct {
	mu    sync.Mutex
	calls int
	route core.Route
	err   error
	echo  core.Target
}

func newStubDialer(echo core.Target) *stubDialer {
	return &stubDialer{
		route: core.Route{Action: core.RouteProxy, Label: "stub-node"},
		echo:  echo,
	}
}

func (d *stubDialer) DialTarget(ctx context.Context, _ core.Target) (net.Conn, core.Route, error) {
	d.mu.Lock()
	d.calls++
	route, err := d.route, d.err
	d.mu.Unlock()
	if err != nil {
		return nil, route, err
	}
	conn, dialErr := (&net.Dialer{}).DialContext(ctx, "tcp", d.echo.String())
	return conn, route, dialErr
}

func (d *stubDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func (d *stubDialer) setErr(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.err = err
}

func (d *stubDialer) currentRoute() core.Route {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.route
}

// telemetryRecorder 记录 core.Telemetry 三类事件（记录器假件，§8.4）。
type telemetryRecorder struct {
	mu       sync.Mutex
	opened   []string
	rejected []string // "proto/reason"
	done     []core.ConnAttrs
}

func (r *telemetryRecorder) ConnOpened(proto string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opened = append(r.opened, proto)
}

func (r *telemetryRecorder) ConnRejected(proto, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejected = append(r.rejected, proto+"/"+reason)
}

func (r *telemetryRecorder) ConnDone(a core.ConnAttrs) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.done = append(r.done, a)
}

func (r *telemetryRecorder) snapshot() (opened, rejected []string, done []core.ConnAttrs) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.opened...), append([]string(nil), r.rejected...), append([]core.ConnAttrs(nil), r.done...)
}

// waitDone 轮询直到恰好出现 n 条 ConnDone（或超时），返回事件快照。
func waitDone(t *testing.T, tel *telemetryRecorder, n int) (opened, rejected []string, done []core.ConnAttrs) {
	t.Helper()
	deadline := time.Now().Add(suiteEventWait)
	for {
		opened, rejected, done = tel.snapshot()
		if len(done) >= n {
			return opened, rejected, done
		}
		if time.Now().After(deadline) {
			return opened, rejected, done
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitRejection 轮询直到出现首个拒绝或终态事件（或超时），返回事件快照。
func waitRejection(t *testing.T, tel *telemetryRecorder) (opened, rejected []string, done []core.ConnAttrs) {
	t.Helper()
	deadline := time.Now().Add(suiteEventWait)
	for {
		opened, rejected, done = tel.snapshot()
		if len(rejected)+len(done) > 0 {
			return opened, rejected, done
		}
		if time.Now().After(deadline) {
			return opened, rejected, done
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// startEchoServer 启动回环回显上游（假出站的拨号目标）：读到的字节原样
// 写回；一侧 EOF 后关闭连接（配合半关闭检查）。
func startEchoServer(t *testing.T) core.Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("testutil: echo listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return core.Target{Host: "127.0.0.1", Port: uint16(addr.Port)}
}

// roundTrip 做一次双向字节往返：写出载荷并原样读回。
func roundTrip(conn net.Conn, payload string) error {
	if _, err := conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(got) != payload {
		return fmt.Errorf("round trip payload mismatch: got %q", got)
	}
	return nil
}

// contains 报告列表中是否含给定项。
func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// joinErrors 拼接违例列表（失败时输出全部违例，便于一次修全）。
func joinErrors(errs []error) string {
	msgs := make([]string, 0, len(errs))
	for _, err := range errs {
		msgs = append(msgs, "- "+err.Error())
	}
	return strings.Join(msgs, "\n")
}
