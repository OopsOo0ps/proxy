package serverapp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/testutil"
	"github.com/OopsOo0ps/proxy/internal/trojan"
	"gopkg.in/yaml.v3"
)

// trojanParams 把服务端 trojan 入站的协议参数编码为 yaml.Node
// （与严格解码路径一致；内部测试包无法复用 serverapp_test 的同名助手）。
func trojanParams(t *testing.T, certFile, keyFile, username, password string) yaml.Node {
	t.Helper()
	body := "cert-file: " + strconv.Quote(certFile) + "\n" +
		"key-file: " + strconv.Quote(keyFile) + "\n" +
		"users:\n  - username: " + strconv.Quote(username) + "\n    password: " + strconv.Quote(password) + "\n"
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	return *doc.Content[0]
}

// rollbackCfg 构造显式端口的 trojan 入站配置（回滚重绑按显式地址恢复原端口）。
// 运维端点未启用（api.listen 为空）：回滚路径只涉及隧道监听。
func rollbackCfg(t *testing.T, listen string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, err := testutil.WriteTLSCertFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	trojanParamsNode := trojanParams(t, certFile, keyFile, "alice", "secret")
	return &config.Config{
		Inbounds: []config.Inbound{{Type: config.TypeTrojan, Listen: listen, Params: trojanParamsNode}},
		Timeouts: config.Timeouts{
			Dial:      config.Duration(3 * time.Second),
			Handshake: config.Duration(3 * time.Second),
			Idle:      config.Duration(30 * time.Second),
		},
		Log: config.Log{Level: "error", Format: "json"},
	}
}

// freeLoopbackAddr 返回一个当前空闲的环回地址（探测监听随即释放）。
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// holdLoopbackListener 绑定并持有占用一个环回地址的监听（制造绑定冲突，
// 由测试全程持有，不依赖竞态窗口）。
func holdLoopbackListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// startServingApp 启动 Serve 循环并等待其上线（Serving 置位：此后 Reload
// 失败时 restore 会以新代际恢复服务）。返回 Serve 的退出错误通道。
func startServingApp(t *testing.T, app *App) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		served <- app.Serve(ctx)
		close(exited)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for !app.Serving() {
		if time.Now().After(deadline) {
			t.Fatal("app did not start serving")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return served
}

// startEchoTarget 启动回显 TCP 服务（把收到的内容原样写回）。
func startEchoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

// tunnelEcho 经 Trojan 隧道把 payload 发往 target 并读取回显。
func tunnelEcho(t *testing.T, app *App, password, target, payload string) string {
	t.Helper()
	host, portString, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := trojan.Dial(ctx, trojan.ClientConfig{
		ServerAddr:       app.TunnelAddr(),
		Password:         password,
		TLSConfig:        &tls.Config{InsecureSkipVerify: true},
		DialTimeout:      3 * time.Second,
		HandshakeTimeout: 3 * time.Second,
	}, core.Target{Host: host, Port: uint16(port)})
	if err != nil {
		t.Fatalf("trojan dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("tunnel write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("tunnel read: %v", err)
	}
	return string(buf[:n])
}

// TestReloadSwitchBindFailureRollsBack 验证回滚成功路径：新配置的入站监听
// 与测试持有的端口冲突 → switchTo 绑新失败 → restore 重建旧监听：旧隧道
// 仍可通、Reload 返回错误、运行时未切换。
func TestReloadSwitchBindFailureRollsBack(t *testing.T) {
	target := startEchoTarget(t)

	oldAddr := freeLoopbackAddr(t)
	cfg := rollbackCfg(t, oldAddr)
	app, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	served := startServingApp(t, app)

	// 切换阶段绑定失败：新监听端口被测试全程持有（确定性冲突）。
	next := rollbackCfg(t, holdLoopbackListener(t))
	if err := app.Reload(next); err == nil {
		t.Fatal("reload with conflicting listener must fail")
	} else if !strings.Contains(err.Error(), "bind new configuration") {
		t.Fatalf("reload error should report the switch-stage bind failure: %v", err)
	}

	// 旧监听被恢复：地址不变，运行时未切换（cfg 指针一致）。
	if got := app.TunnelAddr(); got != oldAddr {
		t.Fatalf("old listener not restored: addr = %q, want %q", got, oldAddr)
	}
	if rt := app.live.Load(); rt.cfg != cfg {
		t.Fatal("runtime switched despite failed reload")
	}

	// Serve 未被一次回滚成功的失败重载终止。
	select {
	case err := <-served:
		t.Fatalf("Serve exited on a rolled-back reload: %v", err)
	case <-time.After(250 * time.Millisecond):
	}

	// 旧隧道仍可通：凭据未变，回显目标经隧道可达。
	if got := tunnelEcho(t, app, "secret", target, "ping-rollback"); got != "ping-rollback" {
		t.Fatalf("tunnel after rollback: echo = %q", got)
	}
}

// TestReloadRollbackKeepsEphemeralAdminPort 验证运维端点回滚端口稳定
// （open-items #3）：api.listen 为 :0 时，失败重载的回滚重绑（restore 的
// Bind(cur, cur)）保持运维端点原监听地址——status.Server 关闭后自身 Addr()
// 为空串，端口提示取自 bindRuntime 记录的 adminAddr；成功重载（Bind(next,
// cur)）的同端口稳定一并在本用例断言：两条路径都不得迁移 :0 运维端点
// （固定端口行为由 TestReloadSwitchBindFailureRollsBack 覆盖）。
func TestReloadRollbackKeepsEphemeralAdminPort(t *testing.T) {
	target := startEchoTarget(t)

	cfg := rollbackCfg(t, "127.0.0.1:0")
	cfg.API.Listen = "127.0.0.1:0"
	app, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	served := startServingApp(t, app)
	tunnelBefore, adminBefore := app.TunnelAddr(), app.MetricsAddr()
	if tunnelBefore == "" || adminBefore == "" {
		t.Fatalf("endpoints not bound: tunnel=%q admin=%q", tunnelBefore, adminBefore)
	}

	// 切换阶段绑定失败：新入站监听端口被测试全程持有（确定性冲突），运维
	// 端点保持 :0——绑新在入站处失败进入 restore，两个 :0 端点都按旧地址重绑。
	next := rollbackCfg(t, holdLoopbackListener(t))
	next.API.Listen = "127.0.0.1:0"
	if err := app.Reload(next); err == nil {
		t.Fatal("reload with conflicting listener must fail")
	} else if !strings.Contains(err.Error(), "bind new configuration") {
		t.Fatalf("reload error should report the switch-stage bind failure: %v", err)
	}

	// 回滚端口稳定：:0 隧道入站与运维端点的监听地址都与重载前一致。
	if got := app.TunnelAddr(); got != tunnelBefore {
		t.Fatalf("rollback moved the :0 tunnel listener: %s -> %s", tunnelBefore, got)
	}
	if got := app.MetricsAddr(); got != adminBefore {
		t.Fatalf("rollback moved the :0 admin listener: %s -> %s", adminBefore, got)
	}
	if rt := app.live.Load(); rt.cfg != cfg {
		t.Fatal("runtime switched despite failed reload")
	}
	waitForAdminOK(t, adminBefore)

	// 成功重载（同 :0 配置，换证书触发真实重建）：运维端点地址依旧不变。
	nextOK := rollbackCfg(t, "127.0.0.1:0")
	nextOK.API.Listen = "127.0.0.1:0"
	if err := app.Reload(nextOK); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := app.TunnelAddr(); got != tunnelBefore {
		t.Fatalf("successful reload moved the :0 tunnel listener: %s -> %s", tunnelBefore, got)
	}
	if got := app.MetricsAddr(); got != adminBefore {
		t.Fatalf("successful reload moved the :0 admin listener: %s -> %s", adminBefore, got)
	}
	waitForAdminOK(t, adminBefore)

	// Serve 未被回滚与重载终止。
	select {
	case err := <-served:
		t.Fatalf("Serve exited: %v", err)
	case <-time.After(250 * time.Millisecond):
	}

	// 隧道在回滚与重载后仍可通（凭据未变；测试证书经 InsecureSkipVerify 直连）。
	if got := tunnelEcho(t, app, "secret", target, "ping-admin-stable"); got != "ping-admin-stable" {
		t.Fatalf("tunnel after reloads: echo = %q", got)
	}
}

// waitForAdminOK 轮询运维端点 /health 直到返回 200（代际切换后 Serve 协程
// 拉起的短窗口内允许重试；超时判失败）。
func waitForAdminOK(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/health")
		if err == nil {
			code := resp.StatusCode
			_ = resp.Body.Close()
			if code == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("admin endpoint %s did not serve /health 200", addr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestReloadRollbackFailureFailsClosed 验证回滚失败 → fail-closed：
// 注入 restore 的绑定失败（旧监听无法重建）后，Reload 返回错误且 Serve
// 退出并上报该错误——进程不以零监听状态静默存活，交由进程管理器重启。
// 构造方式：bind 闭包只被重载重绑路径调用，正常运行不经它，因此把旧运行时
// 入站的 bind 换成必定失败的实现即可确定性地令 restore 失败（无竞态窗口）。
func TestReloadRollbackFailureFailsClosed(t *testing.T) {
	cfg := rollbackCfg(t, freeLoopbackAddr(t))
	app, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	served := startServingApp(t, app)

	// 注入点：旧运行时入站的重绑闭包直接失败。
	cur := app.live.Load()
	cur.Inbounds[0].bind = func(_ *connlimit.Limiter, _ string) (inboundBound, error) {
		return inboundBound{}, errors.New("injected: restore bind failure")
	}

	// 绑新同样失败（端口被测试持有）：进入 restore，而 restore 注入失败。
	next := rollbackCfg(t, holdLoopbackListener(t))
	if err := app.Reload(next); err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("reload must report the rollback failure: %v", err)
	}

	// fail-closed：Serve 退出且错误上报（fail → appCancel → firstErr）。
	select {
	case serr := <-served:
		if serr == nil || !strings.Contains(serr.Error(), "rollback") {
			t.Fatalf("Serve error should surface the rollback failure: %v", serr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit after failed rollback; process would linger with zero listeners")
	}
}
