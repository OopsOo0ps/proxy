package relay

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
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
