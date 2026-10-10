package relay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

// tcpPair 建立一对本地 TCP 连接用于测试。
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	acceptCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- conn
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case server := <-acceptCh:
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, server
	case err := <-errCh:
		t.Fatalf("accept: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("accept timeout")
	}
	return nil, nil
}

func TestBiCopyEcho(t *testing.T) {
	client, clientSide := tcpPair(t)
	server, serverSide := tcpPair(t)

	// relay 层：client <-> server；把 clientSide 与 serverSide 对接。
	done := make(chan Stats, 1)
	var relayErr error
	go func() {
		stats, err := BiCopy(context.Background(), clientSide, serverSide, 5*time.Second)
		relayErr = err
		done <- stats
	}()

	payload := []byte("hello relay")
	go func() {
		_, _ = client.Write(payload)
		_ = client.(*net.TCPConn).CloseWrite()
	}()

	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server received %q, want %q", got, payload)
	}
	if _, err := server.Write([]byte("ack")); err != nil {
		t.Fatalf("write ack: %v", err)
	}
	_ = server.(*net.TCPConn).CloseWrite()

	reply, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(reply) != "ack" {
		t.Fatalf("client received %q, want ack", reply)
	}

	stats := <-done
	if relayErr != nil {
		t.Fatalf("BiCopy error: %v", relayErr)
	}
	if stats.ClientToUpstream != int64(len(payload)) {
		t.Fatalf("ClientToUpstream = %d, want %d", stats.ClientToUpstream, len(payload))
	}
	if stats.UpstreamToClient != 3 {
		t.Fatalf("UpstreamToClient = %d, want 3", stats.UpstreamToClient)
	}
}

func TestBiCopyHalfClosePreservesData(t *testing.T) {
	client, clientSide := tcpPair(t)
	server, serverSide := tcpPair(t)

	done := make(chan error, 1)
	go func() {
		_, err := BiCopy(context.Background(), clientSide, serverSide, 5*time.Second)
		done <- err
	}()

	// 大块数据 + 立即半关闭：验证对端能读全，不因提前关闭丢数据。
	big := bytes.Repeat([]byte("0123456789abcdef"), 64*1024) // 1 MiB
	go func() {
		_, _ = client.Write(big)
		_ = client.(*net.TCPConn).CloseWrite()
	}()

	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != len(big) {
		t.Fatalf("received %d bytes, want %d", len(got), len(big))
	}

	_ = server.Close()
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil && !IsExpected(err) {
			t.Fatalf("unexpected relay error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not finish")
	}
}

func TestBiCopyIdleTimeout(t *testing.T) {
	client, clientSide := tcpPair(t)
	server, serverSide := tcpPair(t)
	_ = client
	_ = server

	start := time.Now()
	_, err := BiCopy(context.Background(), clientSide, serverSide, 150*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "idle") {
		t.Fatalf("err = %v, want idle timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("idle timeout took %v", elapsed)
	}
}

func TestBiCopyContextCancel(t *testing.T) {
	client, clientSide := tcpPair(t)
	server, serverSide := tcpPair(t)
	_ = client
	_ = server

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = BiCopy(ctx, clientSide, serverSide, time.Minute)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("BiCopy did not stop after context cancel")
	}
}

func TestPrefixConnServesBufferedData(t *testing.T) {
	client, serverSide := tcpPair(t)

	// 模拟 Hijack 场景：bufio.Reader 已预读部分数据，转发时不能丢掉它们。
	go func() {
		_, _ = client.Write([]byte("hello world"))
		_ = client.Close()
	}()

	br := bufio.NewReader(serverSide)
	peek, err := br.Peek(5)
	if err != nil || string(peek) != "hello" {
		t.Fatalf("peek = %q, err = %v", peek, err)
	}

	conn := PrefixConn(serverSide, br)
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("PrefixConn read %q, want %q", got, "hello world")
	}
}

func TestIsExpected(t *testing.T) {
	if !IsExpected(nil) || !IsExpected(io.EOF) || !IsExpected(ErrIdleTimeout) || !IsExpected(net.ErrClosed) {
		t.Fatal("expected errors should be classified as expected")
	}
	if IsExpected(context.DeadlineExceeded) {
		// context.DeadlineExceeded 不在预期列表内（由调用方决定语义）。
		t.Fatal("deadline exceeded should not be classified as expected by default")
	}
}

// TestSideErrorClassification 固化收尾竞态的分类语义：
// 对端主动中止（RST/EPIPE，含两侧）都不计故障，但错误带来源标注。
func TestSideErrorClassification(t *testing.T) {
	clientReset := &SideError{Side: SideClient, Err: syscall.ECONNRESET}
	clientPipe := &SideError{Side: SideClient, Err: syscall.EPIPE}
	clientOther := &SideError{Side: SideClient, Err: errors.New("boom")}
	clientCanceled := &SideError{Side: SideClient, Err: context.Canceled}
	upstreamReset := &SideError{Side: SideUpstream, Err: syscall.ECONNRESET}

	if IsExpected(clientReset) {
		t.Error("对端 RST 不是正常收尾，不应由 IsExpected 判定")
	}
	if !IsPeerAbort(clientReset) || IsFailure(clientReset) {
		t.Error("入站侧 RST 应判定为对端主动中止，不计故障")
	}
	if !IsPeerAbort(clientPipe) || IsFailure(clientPipe) {
		t.Error("入站侧 EPIPE 应判定为对端主动中止，不计故障")
	}
	if IsPeerAbort(clientOther) || !IsFailure(clientOther) {
		t.Error("入站侧普通错误应保留为故障")
	}
	if IsFailure(clientCanceled) {
		t.Error("上下文取消属于正常收尾，不应计故障")
	}
	// Linux 上 TLS 目标站点读到 close_notify 后关闭连接、未读 FIN 触发
	// 内核 RST 是常态收尾竞态，同样不计故障。
	if !IsPeerAbort(upstreamReset) || IsFailure(upstreamReset) {
		t.Error("出站侧 RST 是收尾中止，不计故障")
	}

	// 错误文本带来源标注，供日志定位；errors.Is 应穿透标注。
	if !strings.Contains(clientReset.Error(), "client:") || !strings.Contains(upstreamReset.Error(), "upstream:") {
		t.Errorf("SideError 文本缺少来源标注: %q / %q", clientReset.Error(), upstreamReset.Error())
	}
	if !errors.Is(clientReset, syscall.ECONNRESET) || !errors.Is(upstreamReset, syscall.ECONNRESET) {
		t.Error("SideError 应支持 errors.Is 穿透")
	}
}

// TestBiCopyClientResetIsBenign：入站侧对端在数据已送达后直接 RST（浏览器式
// abortive close），转发应以「对端主动中止」收尾而非故障。
func TestBiCopyClientResetIsBenign(t *testing.T) {
	client, clientSide := tcpPair(t)
	server, serverSide := tcpPair(t)

	var (
		done  = make(chan error, 1)
		stats Stats
	)
	go func() {
		s, err := BiCopy(context.Background(), clientSide, serverSide, 5*time.Second)
		stats = s
		done <- err
	}()

	payload := []byte("req")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read forwarded payload: %v", err)
	}

	// 入站侧对端不发 FIN，直接 RST；随后出站侧半关闭让转发收尾。
	tcp, ok := client.(*net.TCPConn)
	if !ok {
		t.Fatal("client is not *net.TCPConn")
	}
	if err := tcp.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = tcp.Close()
	_ = server.(*net.TCPConn).CloseWrite()

	select {
	case err := <-done:
		if !IsPeerAbort(err) || IsFailure(err) {
			t.Fatalf("client reset should be benign, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("BiCopy did not finish")
	}
	if stats.ClientToUpstream != int64(len(payload)) {
		t.Fatalf("ClientToUpstream = %d, want %d", stats.ClientToUpstream, len(payload))
	}
}

// TestBiCopyUpstreamResetIsPeerAbort：出站侧对端 RST（Linux 上目标站点收尾
// 的常态）同样按对端中止分类、不计故障，但错误来源标注为 upstream。
func TestBiCopyUpstreamResetIsPeerAbort(t *testing.T) {
	client, clientSide := tcpPair(t)
	server, serverSide := tcpPair(t)

	done := make(chan error, 1)
	go func() {
		_, err := BiCopy(context.Background(), clientSide, serverSide, 5*time.Second)
		done <- err
	}()

	tcp, ok := server.(*net.TCPConn)
	if !ok {
		t.Fatal("server is not *net.TCPConn")
	}
	if err := tcp.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = tcp.Close()
	_ = client.(*net.TCPConn).CloseWrite()

	select {
	case err := <-done:
		var se *SideError
		if !errors.As(err, &se) || se.Side != SideUpstream {
			t.Fatalf("reset should originate from upstream, got %v", err)
		}
		if !IsPeerAbort(err) || IsFailure(err) {
			t.Fatalf("upstream reset should be a peer abort, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("BiCopy did not finish")
	}
}

// TestDrainConnAvoidsCloseReset：close 时接收缓冲仍有未读数据会向对端发 RST；
// drainConn 先读空在途字节再关闭，对端应看到干净的 FIN（EOF）。
func TestDrainConnAvoidsCloseReset(t *testing.T) {
	// 对照组：不排空直接关闭 → 对端读到 RST。
	t.Run("without drain", func(t *testing.T) {
		peer, ours := tcpPair(t)
		if _, err := peer.Write([]byte("tail")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond) // 回环投递，确保字节已在接收缓冲
		_ = ours.Close()

		_ = peer.(*net.TCPConn).SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		if _, err := peer.Read(buf); !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("close with unread data should reset peer, got %v", err)
		}
	})

	// 修复行为：drainConn 后关闭 → 对端读到干净 FIN。
	t.Run("with drain", func(t *testing.T) {
		peer, ours := tcpPair(t)
		if _, err := peer.Write([]byte("tail")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		_ = peer.(*net.TCPConn).CloseWrite()

		drainConn(ours)
		_ = ours.Close()

		_ = peer.(*net.TCPConn).SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		n, err := peer.Read(buf)
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("peer should observe clean FIN after drain, got n=%d err=%v", n, err)
		}
	})
}

// BenchmarkCopyLoopPooled 测量真实转发路径（缓冲来自 sync.Pool）：
// 每次迭代搬运 1MiB，观察 allocs/op 以佐证缓冲复用效果。
//
// 用内存管道（net.Pipe）而非 TCP：基准关注的是缓冲分配而非网络性能，
// 大量迭代下逐次建立 TCP 连接会耗尽本机临时端口；内存管道无此问题，
// 且每次迭代建立管道的少量分配在两组对照中相同，不影响差值。
func BenchmarkCopyLoopPooled(b *testing.B) { benchmarkCopyLoop(b, true) }

// BenchmarkCopyLoopUnpooled 是对照组：每次连接新建 32KiB 缓冲，
// 两组 allocs/op 的差值即为缓冲复用省下的分配。
func BenchmarkCopyLoopUnpooled(b *testing.B) { benchmarkCopyLoop(b, false) }

func benchmarkCopyLoop(b *testing.B, pooled bool) {
	const payloadSize = 1 << 20 // 1MiB
	payload := bytes.Repeat([]byte("0123456789abcdef"), payloadSize/16)
	drainBuf := make([]byte, relayBufSize) // 循环外创建，避免污染分配统计

	b.SetBytes(payloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		src, srcPeer := net.Pipe()
		dst, dstPeer := net.Pipe()
		drainDone := make(chan struct{})
		go func() {
			defer close(drainDone)
			for {
				if _, err := dstPeer.Read(drainBuf); err != nil {
					return
				}
			}
		}()
		feederDone := make(chan struct{})
		go func() {
			defer close(feederDone)
			_, _ = srcPeer.Write(payload)
			_ = srcPeer.Close()
		}()
		b.StartTimer()

		var (
			n   int64
			err error
		)
		if pooled {
			n, err = copyLoop(dst, src, 0)
		} else {
			n, err = copyLoopWithBuffer(dst, src, 0, make([]byte, relayBufSize))
		}

		b.StopTimer()
		if err != nil && !errors.Is(err, io.EOF) {
			b.Fatalf("copyLoop: %v", err)
		}
		if n != payloadSize {
			b.Fatalf("copied %d bytes, want %d", n, payloadSize)
		}
		<-feederDone
		_ = dstPeer.Close()
		<-drainDone
		_ = src.Close()
		_ = srcPeer.Close()
		_ = dst.Close()
	}
}
