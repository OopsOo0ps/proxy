package httpproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/dialer"
	"github.com/OopsOo0ps/proxy/internal/routing"
)

// stubDialer 是可注入的 TargetDialer 测试桩。
type stubDialer struct {
	dial  func(ctx context.Context, host string, port uint16) (net.Conn, error)
	route routing.Action
}

func (d *stubDialer) DialTarget(ctx context.Context, host string, port uint16) (net.Conn, dialer.Route, error) {
	if d.dial == nil {
		return nil, dialer.Route{Action: d.route}, errors.New("stub: no dial")
	}
	conn, err := d.dial(ctx, host, port)
	return conn, dialer.Route{Action: d.route}, err
}

func (d *stubDialer) RouteFor(string) routing.Action { return d.route }

// startProxy 启动 HTTP 代理服务并返回其地址。
func startProxy(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("Serve did not stop")
		}
	})
	return ln.Addr().String()
}

// startEcho 启动回显 TCP 服务。
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func echoDialer(t *testing.T) *stubDialer {
	t.Helper()
	return &stubDialer{route: routing.Direct, dial: func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		return net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	}}
}

func TestConnectTunnel(t *testing.T) {
	echoAddr := startEcho(t)
	proxyAddr := startProxy(t, &Server{Dialer: echoDialer(t)})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("status line = %q, want 200", status)
	}
	// 读完响应头。
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	payload := []byte("tunnel data")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestConnectPipelinedPayload(t *testing.T) {
	echoAddr := startEcho(t)
	proxyAddr := startProxy(t, &Server{Dialer: echoDialer(t)})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 单次写入：CONNECT 请求头 + 立即发送的载荷（模拟 TLS ClientHello 紧随其后）。
	payload := []byte("immediate-payload")
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)
	if _, err := conn.Write(append([]byte(req), payload...)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("status line = %q, want 200", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("pipelined payload lost: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestConnectAuth(t *testing.T) {
	echoAddr := startEcho(t)
	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := startProxy(t, &Server{Auth: store, Dialer: echoDialer(t)})

	// 无凭据：407 且带标准质询头。
	resp := rawConnect(t, proxyAddr, echoAddr, "")
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") == "" {
		t.Fatal("407 response must include Proxy-Authenticate")
	}
	body := readAll(t, resp.Body)
	if strings.Contains(strings.ToLower(body), "alice") || strings.Contains(strings.ToLower(body), "user") {
		t.Fatalf("407 body leaks credential hints: %q", body)
	}

	// 错误凭据：407。
	bad := base64.StdEncoding.EncodeToString([]byte("alice:wrong"))
	resp = rawConnect(t, proxyAddr, echoAddr, "Basic "+bad)
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("bad credentials status = %d, want 407", resp.StatusCode)
	}

	// 正确凭据：200。
	good := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	resp = rawConnect(t, proxyAddr, echoAddr, "Basic "+good)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid credentials status = %d, want 200", resp.StatusCode)
	}
}

// rawConnect 通过原始 HTTP 请求发起 CONNECT，返回解析后的响应。
func rawConnect(t *testing.T, proxyAddr, target, proxyAuth string) *http.Response {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if proxyAuth != "" {
		req += "Proxy-Authorization: " + proxyAuth + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(data)
}

func TestConnectDialFailure(t *testing.T) {
	srv := &Server{Dialer: &stubDialer{route: routing.Proxy, dial: func(context.Context, string, uint16) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}}}
	proxyAddr := startProxy(t, srv)

	resp := rawConnect(t, proxyAddr, "example.com:443", "")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestForwardAbsoluteForm(t *testing.T) {
	var gotProxyAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProxyAuth = r.Header.Get("Proxy-Authorization")
		_, _ = w.Write([]byte("hello from target"))
	}))
	defer target.Close()

	proxyAddr := startProxy(t, &Server{Dialer: &stubDialer{route: routing.Direct, dial: func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		return net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	}}})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	cred := base64.StdEncoding.EncodeToString([]byte("u:p"))
	req := fmt.Sprintf("GET %s/ HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nProxy-Connection: keep-alive\r\n\r\n",
		target.URL, strings.TrimPrefix(target.URL, "http://"), cred)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body := readAll(t, resp.Body); body != "hello from target" {
		t.Fatalf("body = %q", body)
	}
	if gotProxyAuth != "" {
		t.Fatalf("Proxy-Authorization must not be forwarded to origin, got %q", gotProxyAuth)
	}
}

func TestForwardRejectsRelativeForm(t *testing.T) {
	proxyAddr := startProxy(t, &Server{Dialer: &stubDialer{route: routing.Direct}})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestForwardUpstreamError(t *testing.T) {
	proxyAddr := startProxy(t, &Server{Dialer: &stubDialer{route: routing.Direct, dial: func(context.Context, string, uint16) (net.Conn, error) {
		return nil, errors.New("boom")
	}}})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestSplitHostPortDefault(t *testing.T) {
	cases := []struct {
		in       string
		defPort  uint16
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{"example.com:8443", 443, "example.com", 8443, false},
		{"example.com", 443, "example.com", 443, false},
		{"[::1]:8443", 443, "::1", 8443, false},
		{"::1", 443, "::1", 443, false},
		{"1.2.3.4:80", 443, "1.2.3.4", 80, false},
		{"1.2.3.4", 80, "1.2.3.4", 80, false},
		{"example.com:0", 443, "", 0, true},
		{"example.com:abc", 443, "", 0, true},
		{"", 443, "", 0, true},
	}
	for _, tc := range cases {
		host, port, err := splitHostPortDefault(tc.in, tc.defPort)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("splitHostPortDefault(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("splitHostPortDefault(%q): %v", tc.in, err)
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Fatalf("splitHostPortDefault(%q) = (%q, %d), want (%q, %d)", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

func TestParseBasicAuth(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	if user, pass, ok := parseBasicAuth("Basic " + good); !ok || user != "alice" || pass != "s3cret" {
		t.Fatalf("parseBasicAuth = (%q, %q, %v)", user, pass, ok)
	}
	if user, pass, ok := parseBasicAuth("basic " + good); !ok || user != "alice" || pass != "s3cret" {
		t.Fatal("scheme matching should be case-insensitive")
	}
	for _, bad := range []string{"", "Bearer token", "Basic !!!notbase64!!!", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon"))} {
		if _, _, ok := parseBasicAuth(bad); ok {
			t.Fatalf("parseBasicAuth(%q) should fail", bad)
		}
	}
}
