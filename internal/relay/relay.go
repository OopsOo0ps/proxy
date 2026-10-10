// Package relay 提供双向流量转发原语：处理半关闭、空闲超时与上下文取消。
package relay

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
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

// closeWriter 是支持半关闭写方向的连接（*net.TCPConn、*tls.Conn 均实现）。
type closeWriter interface{ CloseWrite() error }

var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

// BiCopy 在 client 与 upstream 之间双向复制数据，直到两侧结束、空闲超时或 ctx 取消。
//
// 语义细节：
//   - 一侧读到 EOF 时对另一侧执行半关闭（CloseWrite），保证对端能收到完整数据；
//   - 每次成功读取后重置读超时，实现“空闲超时”而非“总时长超时”；
//   - ctx 取消时立即关闭两端，让阻塞中的读写退出。
//
// 返回值中的 error 是除正常 EOF 外的首个异常（含 ErrIdleTimeout）。
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

	record := func(err error) {
		if err == nil || errors.Is(err, io.EOF) {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
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
		record(err)
	}()
	go func() {
		defer wg.Done()
		var err error
		toClient, err = copyLoop(client, upstream, idle)
		halfClose(client)
		record(err)
	}()

	wg.Wait()
	close(exited)
	closeBoth()
	mu.Lock()
	defer mu.Unlock()
	return Stats{ClientToUpstream: toUpstream, UpstreamToClient: toClient}, firstErr
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
	buf := *bufPtr

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
