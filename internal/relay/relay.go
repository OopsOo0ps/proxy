// Package relay 提供双向流量转发原语：处理半关闭、空闲超时与上下文取消。
//
// 收尾语义（连接拆除阶段的 RST/FIN 竞态）：
//   - 对端主动中止（TCP RST / EPIPE）不按本端转发故障处理（见 IsPeerAbort）。
//     双方都可能触发：浏览器读满响应后直接关闭（内核因接收缓冲有未读数据
//     发 RST）；Linux 上 TLS 目标站点读到 close_notify 后关闭连接、未读的
//     FIN 令内核发出 RST；proxy-client 与 proxy-server 同理。此时数据往往
//     已完整送达，只是收尾记录会被误归为异常。
//   - RST/EPIPE 无法与「传输中途被截断」区分（本层看不到应用语义），
//     因此不吞掉错误细节：完成日志保留带来源（client / upstream）标注的
//     error 字段；指标 result 只区分「正常收尾（含对端中止）」与「异常」。
//   - BiCopy 正常结束后会先做一次有界排空（见 closeGrace）再关闭两端，
//     避免本端 close 时接收缓冲仍有未读数据、向对端发出 RST，把一次
//     完整送达的转发留给对端一个「异常中止」的印象。
package relay

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
)

// ErrIdleTimeout 表示连接因空闲超时被关闭。
var ErrIdleTimeout = errors.New("relay: idle timeout")

// Stats 汇总一次双向转发的字节数。
type Stats struct {
	// ClientToUpstream 是客户端到上游方向的字节数。
	ClientToUpstream int64
	// UpstreamToClient 是上游到客户端方向的字节数。
	UpstreamToClient int64
}

// Side 标识双向转发的端点归属。
type Side uint8

const (
	// SideClient 是入站侧：HTTP/SOCKS5 场景下的浏览器，隧道服务端场景下的 proxy-client。
	SideClient Side = iota + 1
	// SideUpstream 是出站侧：直连目标站点，或 proxy-client 场景下的出口节点隧道。
	SideUpstream
)

func (s Side) String() string {
	switch s {
	case SideClient:
		return "client"
	case SideUpstream:
		return "upstream"
	default:
		return "unknown"
	}
}

// SideError 为转发错误标注来源端点，供调用方区分「入站侧对端中止」与
// 「出站侧中止」（日志定位用；分类见 IsPeerAbort / IsFailure）。
type SideError struct {
	Side Side
	Err  error
}

func (e *SideError) Error() string { return e.Side.String() + ": " + e.Err.Error() }
func (e *SideError) Unwrap() error { return e.Err }

// closeWriter 是支持半关闭写方向的连接（*net.TCPConn、*tls.Conn 均实现）。
type closeWriter interface{ CloseWrite() error }

// relayBufSize 是单个方向的转发缓冲大小：32KiB 与 io.Copy 的缺省一致，
// 大于 TLS 记录上限（16KiB），减少单次读写的系统调用次数，同时把每连接
// 的常驻内存控制在合理范围（双向合计 64KiB）。
const relayBufSize = 32 * 1024

// closeGrace 是正常结束后、真正关闭前的排空窗口。
//
// 直接 close 一个接收缓冲仍有未读数据的 socket 会向对端发送 RST；对端
// （包括本项目的 server/client 与真实浏览器）会把一次「数据已完整送达、
// 只是收尾字节在途」的转发记为异常中止。这里用「有界排空到 EOF」等价于
// net/http 服务端在关闭前的 rstAvoidanceDelay 等待（RFC 7230 §6.6 的
// lingering close 建议），并额外把已到达的字节读完，确保 close 不触发 RST。
const closeGrace = 500 * time.Millisecond

// bufPool 复用转发缓冲，降低高并发下的 GC 压力。
//
// 设计理由：
//   - 每条转发连接每个方向各占一条缓冲；若逐连接创建，1000 条并发连接
//     会持续产生约 64MiB 的瞬时垃圾，给 GC 带来与流量无关的固定压力，
//     复用后大部分连接不再产生这块分配；
//   - 池中存放 *[]byte 而不是 []byte：把切片头装进 any 会迫使切片头
//     逃逸到堆上（每次 Put/Get 都多一次分配），存指针可以完全避免；
//   - 每个方向只有一条缓冲，同时承担读与写（读到的字节立即写出），
//     相比"读缓冲 + 写缓冲"省掉一半内存，也不引入额外拷贝；
//   - 归还的缓冲不做清零：转发数据是过路流量，下一次使用会先写满
//     已读到的字节再写出，不会把旧数据带给对端。
var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, relayBufSize)
		return &buf
	},
}

// BiCopy 在 client 与 upstream 之间双向复制数据，直到两侧结束、空闲超时或 ctx 取消。
//
// 语义细节：
//   - 一侧读到 EOF 时对另一侧执行半关闭（CloseWrite），保证对端能收到完整数据；
//   - 每次成功读取后重置读超时，实现“空闲超时”而非“总时长超时”；
//   - ctx 取消时立即关闭两端，让阻塞中的读写退出。
//   - 正常结束时先做有界排空再关闭（见 closeGrace），避免向对端发出 RST。
//
// 返回值中的 error 是除正常 EOF 外的首个异常（含 ErrIdleTimeout），
// 并以 *SideError 标注来源端点；分类判断用 IsExpected / IsPeerAbort / IsFailure。
func BiCopy(ctx context.Context, client, upstream net.Conn, idle time.Duration) (Stats, error) {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	exited := make(chan struct{})
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = client.Close()
			_ = upstream.Close()
		})
	}
	defer closeBoth()

	// ctx 取消（进程关停等）时立即关闭两端。
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-exited:
		}
	}()

	record := func(side Side, err error) {
		if err == nil || errors.Is(err, io.EOF) {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = &SideError{Side: side, Err: err}
		}
		mu.Unlock()
	}

	var toUpstream, toClient int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		var err error
		toUpstream, err = copyLoop(upstream, client, idle)
		halfClose(upstream)
		record(SideClient, err)
	}()
	go func() {
		defer wg.Done()
		var err error
		toClient, err = copyLoop(client, upstream, idle)
		halfClose(client)
		record(SideUpstream, err)
	}()

	wg.Wait()
	close(exited)
	// 排空两端仍在途的尾部字节后再关闭：既给对端送达收尾字节的时间，
	// 也避免 close 时接收缓冲未读数据触发 RST（见 closeGrace）。
	var drains sync.WaitGroup
	drains.Add(2)
	go func() { defer drains.Done(); drainConn(client) }()
	go func() { defer drains.Done(); drainConn(upstream) }()
	drains.Wait()
	closeBoth()
	mu.Lock()
	defer mu.Unlock()
	return Stats{ClientToUpstream: toUpstream, UpstreamToClient: toClient}, firstErr
}

// drainConn 在有界窗口内读空 conn 的在途字节（丢弃），用于关闭前避免 RST。
func drainConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(closeGrace))
	_, _ = io.Copy(io.Discard, conn)
}

// halfClose 尝试半关闭写方向；不支持时忽略（连接最终会被整体关闭）。
func halfClose(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// copyLoop 从 src 读取并写入 dst，直到 EOF、空闲超时或错误；
// 返回已写入 dst 的字节数。
func copyLoop(dst, src net.Conn, idle time.Duration) (int64, error) {
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	return copyLoopWithBuffer(dst, src, idle, *bufPtr)
}

// copyLoopWithBuffer 是 copyLoop 的实现主体，缓冲由调用方提供
// （真实路径来自 bufPool；基准测试用它构造"不复用缓冲"的对照组）。
func copyLoopWithBuffer(dst, src net.Conn, idle time.Duration, buf []byte) (int64, error) {
	var total int64
	for {
		if idle > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idle))
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			if idle > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idle))
			}
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return total, writeErr
			}
			total += int64(n)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, io.EOF
			}
			var netErr net.Error
			if errors.As(readErr, &netErr) && netErr.Timeout() {
				return total, ErrIdleTimeout
			}
			return total, readErr
		}
	}
}

// IsExpected 判断错误是否属于正常关闭（EOF、空闲回收、连接已关闭、上下文取消）。
func IsExpected(err error) bool {
	return err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, ErrIdleTimeout) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled)
}

// IsPeerAbort 判断错误是否为对端的主动中止（TCP RST / EPIPE）。
//
// 典型场景都是收尾竞态：浏览器读满响应后关闭连接（内核因接收缓冲仍有
// 未读数据发 RST）；Linux 上 TLS 目标站点读完 close_notify 后关闭连接、
// 未读 FIN 令内核发出 RST。此时数据通常已完整送达，按正常收尾处理；
// 与「传输中途被截断」在本层不可区分，错误详情（含来源标注）保留在日志中。
func IsPeerAbort(err error) bool {
	return isPeerAbort(err)
}

// IsFailure 判断转发错误是否应记为故障：既非正常收尾（IsExpected），
// 也非对端主动中止（IsPeerAbort）。
func IsFailure(err error) bool {
	return !IsExpected(err) && !IsPeerAbort(err)
}

// isPeerAbort 判断底层错误是否为对端的 abortive close（RST）或写向已关闭
// 对端的 EPIPE。
func isPeerAbort(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// PrefixConn 包装连接，使已被 bufio 预读的字节在后续读取中优先返回。
// 用于 Hijack / 协议握手之后：读取方可能已把载荷读进缓冲区，转发时不能丢。
func PrefixConn(conn net.Conn, r *bufio.Reader) net.Conn {
	if r == nil || r.Buffered() == 0 {
		return conn
	}
	return &prefixConn{Conn: conn, r: r}
}

type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

// Read 优先返回缓冲区中已预读的数据。
func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite 透传底层连接的半关闭能力。
func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// CloseRead 透传底层连接的半关闭能力。
func (c *prefixConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}
