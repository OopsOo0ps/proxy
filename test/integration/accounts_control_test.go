// TestAccountsControl 是订阅门禁迭代①的黑盒用例（实施规划 §6 黑盒行，
// 设计书 §1.1 I2 / §3.2）：起真 proxy-server（accounts 模式 + 环回控制面 +
// 无静态用户的 trojan 入站），全程只经进程边界验证：
//
//  1. 控制面 CRUD：POST /users 创建 → GET /users 列表 → PATCH 停用 →
//     PATCH 重新启用 → PUT /users/{name}/subscription 设置 expires_at；
//  2. accounts 创建的用户真实走通代理（端到端隧道 + 服务端完成日志的
//     user 字段 = 该用户名，黑盒证明动态凭据被服务端采纳）；
//  3. 停用用户的拒绝与认证失败同形（trojan 伪装页，设计书 §1.1 I2：
//     拒绝词汇统一，线上不携带原因细分），且不发生任何路由（无新的
//     隧道完成记录）。
//
// 黑盒边界：不 import internal/accounts / internal/control——账户形状经
// JSON 序列化观测，隧道握手按线格式手工编码（与 socks5Connect 同一手法）。
package integration

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/testutil"
)

func TestAccountsControl(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and runs the real binaries; skipped with -short")
	}

	dir := t.TempDir()
	certFile, keyFile, err := testutil.WriteTLSCertFiles(dir)
	if err != nil {
		t.Fatalf("write TLS cert: %v", err)
	}

	// 目标站点：经隧道以 localhost 域名访问（不命中直连规则，走默认 proxy，
	// 出口侧解析后回连本机——与 3.7 集成主链路相同的技巧）。
	target := startTargetOn(t, "127.0.0.1:0", "accounts-ok", true)
	targetURL := "https://localhost:" + portOf(t, target.Listener.Addr().String())
	targetHost, targetPortStr, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split target %q: %v", target.Listener.Addr().String(), err)
	}
	targetPort, err := strconv.ParseUint(targetPortStr, 10, 16)
	if err != nil {
		t.Fatalf("parse target port %q: %v", targetPortStr, err)
	}

	// 控制面监听地址：listening 日志只回显 tunnel/metrics（cmd/server/main.go），
	// 控制面地址不在其列，黑盒只能预选固定环回端口（复用混沌用例的高段分配器）。
	controlAddr := freeFixedPort(t)

	// 空账户库：文件必须存在（严格加载，缺失即启动失败），空列表合法（空库语义）。
	accountsFile := writeFile(t, dir, "accounts.json", `{"version":1,"users":[]}`)

	// ---- 启动 proxy-server：accounts 模式 + 控制面 + 无静态用户的 trojan 入站 ----
	serverConfig := writeFile(t, dir, "server.yaml", fmt.Sprintf(`
log:
  level: info
  format: json
api:
  listen: "127.0.0.1:0"
control:
  listen: %q
accounts:
  file: %q
inbounds:
  - type: trojan
    listen: "127.0.0.1:0"
    params:
      cert-file: %q
      key-file: %q
`, controlAddr, accountsFile, certFile, keyFile))
	serverProc := startProcess(t, "proxy-server", filepath.Join(binDir, "proxy-server"), "-config", serverConfig)
	serverListen := waitForRecords(t, serverProc, "listening", 1, 10*time.Second)[0]
	tunnelAddr := strField(t, serverProc, serverListen, "tunnel")
	serverMetricsAddr := strField(t, serverProc, serverListen, "metrics")
	waitForStatusOK(t, serverMetricsAddr, 10*time.Second)

	// ---- 控制面 CRUD（真实 HTTP，仅环回）----
	// 起点证明：无静态用户 ⇒ 账户库启动为空。
	if got := fetchBody(t, "http://"+controlAddr+"/users"); strings.TrimSpace(got) != `{"users":[]}` {
		t.Fatalf("启动后 GET /users = %s, want 空账户库 {\"users\":[]}", got)
	}

	username, password := "sub-user", "accounts-secret"
	created := controlRequest(t, controlAddr, http.MethodPost, "/users",
		fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), http.StatusCreated)
	var createdUser controlUserView
	if err := json.Unmarshal([]byte(created), &createdUser); err != nil {
		t.Fatalf("parse POST /users response %s: %v", created, err)
	}
	if createdUser.Username != username || createdUser.Status != "active" {
		t.Fatalf("POST /users = %+v, want username=%s status=active", createdUser, username)
	}

	// 列表包含新建用户；且绝不回显任何凭据字段（明文与摘要都不出控制面）。
	listBody := fetchBody(t, "http://"+controlAddr+"/users")
	var list controlListResponse
	if err := json.Unmarshal([]byte(listBody), &list); err != nil {
		t.Fatalf("parse GET /users response %s: %v", listBody, err)
	}
	var listed *controlUserView
	for i := range list.Users {
		if list.Users[i].Username == username {
			listed = &list.Users[i]
		}
	}
	if listed == nil {
		t.Fatalf("GET /users 列表缺少 %s：%s", username, listBody)
	}
	if listed.Status != "active" {
		t.Errorf("GET /users 中 %s status = %q, want active", username, listed.Status)
	}
	if listed.Subscription != nil {
		t.Errorf("新建用户不应已有订阅：%+v", listed.Subscription)
	}
	if strings.Contains(listBody, "password") {
		t.Errorf("GET /users 响应回显了凭据字段：%s", listBody)
	}

	// 停用 → 重新启用（只停用不删除，设计书 §1.2）。
	disabled := controlRequest(t, controlAddr, http.MethodPatch, "/users/"+username,
		`{"status":"disabled"}`, http.StatusOK)
	var disabledUser controlUserView
	if err := json.Unmarshal([]byte(disabled), &disabledUser); err != nil {
		t.Fatalf("parse PATCH /users response %s: %v", disabled, err)
	}
	if disabledUser.Status != "disabled" {
		t.Fatalf("PATCH 停用后 status = %q, want disabled", disabledUser.Status)
	}
	enabled := controlRequest(t, controlAddr, http.MethodPatch, "/users/"+username,
		`{"status":"active"}`, http.StatusOK)
	var enabledUser controlUserView
	if err := json.Unmarshal([]byte(enabled), &enabledUser); err != nil {
		t.Fatalf("parse PATCH /users response %s: %v", enabled, err)
	}
	if enabledUser.Status != "active" {
		t.Fatalf("PATCH 启用后 status = %q, want active", enabledUser.Status)
	}

	// 管理员设置订阅到期（人工纠错通道，可任意设置）。
	expiresAt := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	subscription := controlRequest(t, controlAddr, http.MethodPut, "/users/"+username+"/subscription",
		fmt.Sprintf(`{"expires_at":%q}`, expiresAt), http.StatusOK)
	var subscribedUser controlUserView
	if err := json.Unmarshal([]byte(subscription), &subscribedUser); err != nil {
		t.Fatalf("parse PUT subscription response %s: %v", subscription, err)
	}
	if subscribedUser.Subscription == nil || subscribedUser.Subscription.ExpiresAt != expiresAt {
		t.Fatalf("PUT subscription 后 = %+v, want subscription.expires_at=%s", subscribedUser, expiresAt)
	}
	// 列表视角再次确认订阅可见。
	listBody = fetchBody(t, "http://"+controlAddr+"/users")
	var finalList controlListResponse
	if err := json.Unmarshal([]byte(listBody), &finalList); err != nil {
		t.Fatalf("parse GET /users response %s: %v", listBody, err)
	}
	for _, u := range finalList.Users {
		if u.Username == username && (u.Subscription == nil || u.Subscription.ExpiresAt != expiresAt) {
			t.Errorf("GET /users 中 %s subscription = %+v, want expires_at=%s", username, u.Subscription, expiresAt)
		}
	}

	// ---- 端到端：accounts 创建的用户真实走通代理 ----
	clientConfig := writeFile(t, dir, "client.yaml", fmt.Sprintf(`
log:
  level: info
  format: json
api:
  listen: "127.0.0.1:0"
inbounds:
  - type: http
    listen: "127.0.0.1:0"
    auth:
      users:
        - username: alice
          password: change-me
outbound:
  nodes:
    - name: node-1
      protocol: trojan
      params:
        addr: %q
        password: %s
        insecure-skip-verify: true
routing:
  private-direct: false
`, tunnelAddr, password))
	clientProc := startProcess(t, "proxy-client", filepath.Join(binDir, "proxy-client"), "-config", clientConfig)
	clientListen := waitForRecords(t, clientProc, "listening", 1, 10*time.Second)[0]
	httpAddr := strField(t, clientProc, clientListen, "http")
	clientMetricsAddr := strField(t, clientProc, clientListen, "metrics")
	waitForStatusOK(t, clientMetricsAddr, 10*time.Second)

	proxyURL, err := url.Parse("http://alice:change-me@" + httpAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	expectBody(t, newProxyClient(t, proxyURL), targetURL, "accounts-ok")
	// 服务端侧独立证据：隧道完成记录的 user 字段 = accounts 创建的用户名。
	tunnelDone := waitForRecords(t, serverProc, "tunnel completed", 1, 10*time.Second)
	if got := strField(t, serverProc, tunnelDone[0], "user"); got != username {
		t.Errorf("服务端隧道完成日志 user = %q, want %q（accounts 创建的用户）", got, username)
	}

	// ---- 停用用户：拒绝与认证失败同形（伪装页），不发生任何路由 ----
	completedBefore := len(records(serverProc.logs, "tunnel completed"))
	controlRequest(t, controlAddr, http.MethodPatch, "/users/"+username,
		`{"status":"disabled"}`, http.StatusOK)

	// 停用用户：口令正确但状态停用 ⇒ 按认证失败通道拒绝。
	disabledResp := trojanRawResponse(t, tunnelAddr, password, targetHost, uint16(targetPort))
	// 对照组：完全未知的口令摘要 ⇒ 同一拒绝通道。
	unknownResp := trojanRawResponse(t, tunnelAddr, "no-such-user-password", targetHost, uint16(targetPort))
	if !strings.Contains(disabledResp, "200 OK") || !strings.Contains(disabledResp, "<!DOCTYPE html>") {
		t.Errorf("停用用户的线上响应不是伪装页：%q", disabledResp)
	}
	if disabledResp != unknownResp {
		t.Errorf("停用用户与认证失败的线上响应不同形：\n停用: %q\n未知: %q", disabledResp, unknownResp)
	}
	// 拒绝走认证失败通道（服务端日志），且未发生任何路由（无新隧道完成记录）。
	if got := len(records(serverProc.logs, "tunnel authentication failed")); got != 2 {
		t.Errorf("tunnel authentication failed 记录 = %d, want 2（停用用户与未知口令各一次）", got)
	}
	if got := len(records(serverProc.logs, "tunnel completed")); got != completedBefore {
		t.Errorf("停用用户被拒绝后出现新的隧道完成记录：%d → %d", completedBefore, got)
	}
}

// —— 本文件的黑盒辅助（复用 integration_test.go / chaos_test.go 的脚手架）——

// controlUserView / controlSubscriptionView 是控制面用户 API 的黑盒形态
// （字段名经 JSON 线上观测；不 import internal/control 保持黑盒边界）。
type controlUserView struct {
	Username     string                   `json:"username"`
	Status       string                   `json:"status"`
	Subscription *controlSubscriptionView `json:"subscription,omitempty"`
}

type controlSubscriptionView struct {
	ExpiresAt string `json:"expires_at"`
	GrantedAt string `json:"granted_at"`
}

// controlListResponse 是 GET /users 的响应信封。
type controlListResponse struct {
	Users []controlUserView `json:"users"`
}

// controlRequest 对控制面执行一次 JSON 请求（真实 TCP + HTTP），校验状态码
// 并返回响应体原文。GET 走 fetchBody；POST/PATCH/PUT 由本辅助覆盖。
func controlRequest(t *testing.T, addr, method, path, body string, wantStatus int) string {
	t.Helper()
	var payload io.Reader
	if body != "" {
		payload = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://"+addr+path, payload)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read body: %v", method, path, err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s %s = %d %s, want %d", method, path, resp.StatusCode, got, wantStatus)
	}
	return string(got)
}

// trojanRawResponse 对 trojan 服务端发起一次原始握手（TLS + 手工编码线格式，
// 黑盒边界），返回服务端响应的全部字节（读到 EOF：伪装页路径服务端会优雅
// 关闭）。线格式：hex(SHA224(password)) CRLF CMD ATYP ADDR PORT CRLF
// （internal/trojan 包文档；地址编码与 SOCKS5 同形，复用 socks5EncodeTarget）。
func trojanRawResponse(t *testing.T, serverAddr, password, targetHost string, targetPort uint16) string {
	t.Helper()
	sum := sha256.Sum224([]byte(password))
	raw, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("dial trojan server %s: %v", serverAddr, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = raw.Close()
		}
	}()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) // 服务端为本地自签证书
	if err := conn.Handshake(); err != nil {
		t.Fatalf("trojan TLS handshake with %s: %v", serverAddr, err)
	}
	addr, err := socks5EncodeTarget(targetHost, targetPort)
	if err != nil {
		t.Fatalf("encode trojan target %s: %v", targetHost, err)
	}
	req := append([]byte(hex.EncodeToString(sum[:])), '\r', '\n', 0x01)
	req = append(req, addr...)
	req = append(req, '\r', '\n')
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("trojan write request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("trojan 读取在收到 EOF 前失败（伪装页路径服务端应优雅关闭）: %v", err)
	}
	ok = true
	_ = conn.Close()
	return string(data)
}
