// 出站传输一致性验收（设计文档 §4.2）。
//
// RunConformance 是传输接入的唯一验收闸门：新出口协议在回环夹具上调用
// 一次即可获得全量正例与负例检查，无需逐条重写断言。检查逻辑拆分为可
// 独立调用的 check* 函数（返回错误列表），供闸门自身的负例测试直接驱动
// ——故意写坏的假实现必须被这套检查拦住，闸门才可信。

package outbound

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

const (
	// conformanceTimeout 是验收中每个网络操作的期限。
	conformanceTimeout = 5 * time.Second
	// poolDwell 模拟连接在预热池中的停留（需小于服务端握手超时）。
	poolDwell = 50 * time.Millisecond
	// dialConcurrency 是并发拨号检查的并发度。
	dialConcurrency = 4
	// roundTripPayload 是往返检查的载荷（往返后原样读回）。
	roundTripPayload = "conformance-round-trip"
)

// RunConformance 对被测传输跑一致性验收：
//   - dial：DialTunnel 一次调用建立绑定到 Target 的就绪隧道，可直接转发
//     原始字节；并发拨号互不串扰；已取消的 ctx 必须失败（假成功识别）；
//   - prewarm（实现 Prewarmer 时）：ConnectIdle 建立空闲句柄，在池中停留
//     后 Bind 补发绑定仍可转发；句柄被 Discard 后 Bind 必须报错，且随后的
//     回退新建（调用方 fallback）仍然可用；已取消的 ctx 必须失败；
//   - probe（实现 Prober 时）：健康端点探测成功；已取消的 ctx 必须失败
//     （假成功识别）。
func RunConformance(t *testing.T, tr Transport) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), conformanceTimeout)
	defer cancel()
	target := startEchoTarget(t)

	if errs := checkDial(ctx, tr, target); len(errs) > 0 {
		t.Errorf("dial checks failed:\n%s", joinErrs(errs))
	}
	if pw, ok := tr.(Prewarmer); ok {
		if errs := checkPrewarm(ctx, tr, pw, target); len(errs) > 0 {
			t.Errorf("prewarm checks failed:\n%s", joinErrs(errs))
		}
	}
	if pb, ok := tr.(Prober); ok {
		if errs := checkProbe(ctx, pb); len(errs) > 0 {
			t.Errorf("probe checks failed:\n%s", joinErrs(errs))
		}
	}
}

// checkDial 验收必备能力：拨通、往返、半关闭、并发拨号与取消语义。
// 对返回形状做防御检查：(nil, nil) 假成功必须被识别。
func checkDial(ctx context.Context, tr Transport, target core.Target) []error {
	var errs []error

	conn, err := tr.DialTunnel(ctx, target)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("DialTunnel: %w", err))
	case conn == nil:
		errs = append(errs, errors.New("DialTunnel returned (nil, nil): fake success"))
	default:
		if err := roundTrip(conn); err != nil {
			errs = append(errs, fmt.Errorf("round trip after dial: %w", err))
		}
		if err := checkHalfClose(conn); err != nil {
			errs = append(errs, fmt.Errorf("half close: %w", err))
		}
		_ = conn.Close()
	}

	var (
		wg  sync.WaitGroup
		ret = make([]error, dialConcurrency)
	)
	for i := 0; i < dialConcurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := tr.DialTunnel(ctx, target)
			if err != nil {
				ret[i] = fmt.Errorf("concurrent DialTunnel #%d: %w", i, err)
				return
			}
			if c == nil {
				ret[i] = fmt.Errorf("concurrent DialTunnel #%d returned (nil, nil)", i)
				return
			}
			if err := roundTrip(c); err != nil {
				ret[i] = fmt.Errorf("concurrent round trip #%d: %w", i, err)
			}
			_ = c.Close()
		}(i)
	}
	wg.Wait()
	for _, err := range ret {
		if err != nil {
			errs = append(errs, err)
		}
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	conn, err = tr.DialTunnel(cctx, target)
	if err == nil {
		errs = append(errs, errors.New("DialTunnel with canceled ctx: expected error"))
		if conn != nil {
			_ = conn.Close()
		}
	}
	return errs
}

// checkPrewarm 验收两阶段预热能力：connect → 池中停留 → bind → 可转发；
// 句柄 Discard 后 bind 必须报错（假实现无视 Discard 即被识别），bind 失败后
// 回退新建仍然可用；已取消 ctx 的两阶段调用必须失败。
func checkPrewarm(ctx context.Context, tr Transport, pw Prewarmer, target core.Target) []error {
	var errs []error

	idle, err := pw.ConnectIdle(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("ConnectIdle: %w", err))
	} else if idle == nil {
		errs = append(errs, errors.New("ConnectIdle returned (nil, nil): fake success"))
	} else {
		time.Sleep(poolDwell)
		conn, err := pw.Bind(ctx, idle, target)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("Bind after dwell: %w", err))
			idle.Discard()
		case conn == nil:
			errs = append(errs, errors.New("Bind returned (nil, nil): fake success"))
			idle.Discard()
		default:
			if err := roundTrip(conn); err != nil {
				errs = append(errs, fmt.Errorf("round trip after bind: %w", err))
			}
			_ = conn.Close()
		}
	}

	// Discard 后 Bind 必须报错：池在 TTL 淘汰/关停时释放句柄，
	// 假实现若不跟踪句柄状态，在这里返回假成功即被识别。
	discarded, err := pw.ConnectIdle(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("ConnectIdle (discard case): %w", err))
	} else if discarded == nil {
		errs = append(errs, errors.New("ConnectIdle returned (nil, nil): fake success"))
	} else {
		discarded.Discard()
		if conn, err := pw.Bind(ctx, discarded, target); err == nil {
			errs = append(errs, errors.New("Bind on discarded handle: expected error"))
			if conn != nil {
				_ = conn.Close()
			}
		}
	}

	// Bind 失败后的回退新建（调用方 fallback 语义）必须可用。
	fresh, err := tr.DialTunnel(ctx, target)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("fallback DialTunnel: %w", err))
	case fresh == nil:
		errs = append(errs, errors.New("fallback DialTunnel returned (nil, nil): fake success"))
	default:
		if err := roundTrip(fresh); err != nil {
			errs = append(errs, fmt.Errorf("fallback round trip: %w", err))
		}
		_ = fresh.Close()
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if idle, err := pw.ConnectIdle(cctx); err == nil {
		errs = append(errs, errors.New("ConnectIdle with canceled ctx: expected error"))
		if idle != nil {
			idle.Discard()
		}
	}
	return errs
}

// checkProbe 验收主动探测能力：健康端点探测成功；已取消 ctx 必须失败
// ——对不可达端点返回假成功的实现在这里被识别。
func checkProbe(ctx context.Context, pb Prober) []error {
	var errs []error
	if err := pb.Probe(ctx); err != nil {
		errs = append(errs, fmt.Errorf("Probe against healthy endpoint: %w", err))
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := pb.Probe(cctx); err == nil {
		errs = append(errs, errors.New("Probe with canceled ctx: expected error (fake success)"))
	}
	return errs
}

// startEchoTarget 启动回环回显服务，返回可穿越被测隧道的目标。
// 回显语义：读到的字节原样写回；一侧 EOF 后关闭连接（配合半关闭检查）。
func startEchoTarget(t *testing.T) core.Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("conformance echo listener: %v", err)
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
func roundTrip(conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(conformanceTimeout)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, roundTripPayload); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	got := make([]byte, len(roundTripPayload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(got) != roundTripPayload {
		return fmt.Errorf("round trip payload mismatch: got %q", got)
	}
	return nil
}

// checkHalfClose 验证半关闭：写出 EOF 后对端关闭，读到回显数据后的 EOF。
// 连接不支持 CloseWrite（如 TLS 隧道）时跳过——该语义由 relay 层保证。
func checkHalfClose(conn net.Conn) error {
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return nil
	}
	if err := conn.SetDeadline(time.Now().Add(conformanceTimeout)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, roundTripPayload); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := cw.CloseWrite(); err != nil {
		return fmt.Errorf("CloseWrite: %w", err)
	}
	got := make([]byte, len(roundTripPayload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if string(got) != roundTripPayload {
		return fmt.Errorf("echo mismatch: got %q", got)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		return errors.New("expected EOF after close write")
	}
	return nil
}

// joinErrs 拼接检查错误列表（验收失败时输出全部违例，便于一次修全）。
func joinErrs(errs []error) string {
	msgs := make([]string, 0, len(errs))
	for _, err := range errs {
		msgs = append(msgs, "- "+err.Error())
	}
	return strings.Join(msgs, "\n")
}
