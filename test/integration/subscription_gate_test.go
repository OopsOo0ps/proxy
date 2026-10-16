// TestSubscriptionGate 是订阅门禁迭代④的黑盒用例（设计书 §1.1 I2、§3 门禁
// 机制、§3.3 fail-closed 链、§5 门禁端到端行「黑盒集成 起真二进制」）：起真
// proxy-server（accounts 模式 + 环回控制面 + 门禁开）与真 proxy-client
// （entitlement 文件门禁 + 入站强制认证），全程只经进程边界验证：
//
//  1. 有效订阅（服务端账户库与客户端 entitlement 双侧一致）：HTTP CONNECT 与
//     SOCKS5 两条链路 client → server → 回环目标全链路成功，服务端隧道完成
//     日志的 user 字段 = 该账户、entitlement_decisions_total{allow} 同步增长
//     ——门禁开启不损伤合法用户；
//  2. 到期 entitlement（管理员重发分发文件 + SIGHUP 热加载）：同一 client
//     进程、同一死出口上，失败类别从「拨号失败（HTTP 502 / SOCKS5 CONNECT
//     阶段应答）」翻转为「认证拒绝（HTTP 407 + Proxy-Authenticate 质询 /
//     SOCKS5 RFC 1929 认证阶段应答）」——唯一变量是订阅有效性，失败类别
//     翻转证明拒绝发生在握手期认证处：门禁拒绝根本不发生拨号（§3.2 零拨号）；
//  3. 服务端是防篡改的墙（§3.1）：非门禁客户端（无 gate 段，本地必然放行）+
//     服务端控制面把订阅置为过去时刻 ⇒ 隧道被服务端拒绝（明文目标拿到伪装
//     页、原始握手与未知口令逐字节同形 I2、deny:expired 决策计数在 /metrics
//     可见）；管理员把订阅延长回未来 ⇒ 同一客户端零改动立即恢复。
//
// 黑盒边界：不 import internal/accounts / internal/control——账户库与
// entitlement 文件按线上 JSON 格式手工构造（摘要现算）、控制面走真实 HTTP、
// 隧道握手按线格式手工编码（复用 trojanRawResponse）。
package integration

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/testutil"
)

func TestSubscriptionGate(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and runs the real binaries; skipped with -short")
	}

	const (
		gateUser     = "sub-user"
		gatePassword = "gate-secret"
		// plainClientUser / plainClientPassword 是非门禁客户端的入站静态凭据
		//（无 gate 段 ⇒ 入站认证退回普通静态凭据，与门禁无关）。
		plainClientUser     = "alice"
		plainClientPassword = "change-me"
	)

	dir := t.TempDir()
	certFile, keyFile, err := testutil.WriteTLSCertFiles(dir)
	if err != nil {
		t.Fatalf("write TLS cert: %v", err)
	}

	// 两个回环目标站点：TLS 目标走 HTTP CONNECT 链路，明文目标走 SOCKS5 与
	// 非门禁客户端的明文 HTTP 链路。都以 localhost 域名访问（不命中直连规则，
	// 走默认 proxy，经隧道到出口侧解析后回连本机——与 3.7 主链路同一技巧）。
	tlsTarget := startTargetOn(t, "127.0.0.1:0", "gate-ok", true)
	tlsTargetAddr := "localhost:" + portOf(t, tlsTarget.Listener.Addr().String())
	tlsTargetURL := "https://" + tlsTargetAddr
	plainTarget := startTargetOn(t, "127.0.0.1:0", "gate-ok", false)
	plainTargetAddr := "localhost:" + portOf(t, plainTarget.Listener.Addr().String())
	plainTargetURL := "http://" + plainTargetAddr
	_, plainTargetPortStr, err := net.SplitHostPort(plainTargetAddr)
	if err != nil {
		t.Fatalf("split plain target %q: %v", plainTargetAddr, err)
	}
	plainTargetPort, err := strconv.ParseUint(plainTargetPortStr, 10, 16)
	if err != nil {
		t.Fatalf("parse plain target port %q: %v", plainTargetPortStr, err)
	}

	// 控制面与死出口都用预选固定环回端口（listening 日志不回显控制面地址，
	// 与控制面用例同一手法；死出口 = 无监听者的空闲端口，拨号立即被拒）。
	controlAddr := freeFixedPort(t)
	deadNodeAddr := freeFixedPort(t)

	// 服务端账户库与客户端 entitlement 文件内容同源（同一版本化 JSON 格式 =
	// 文件分发零转换，设计书 §2.1 accounts 行）。有效订阅：1 小时后到期。
	validUntil := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	grantedAt := validUntil.Add(-24 * time.Hour)
	accountsFile := writeFile(t, dir, "accounts.json", gateAccountsJSON(gateUser, gatePassword, validUntil, grantedAt))
	entitlementFile := writeFile(t, dir, "entitlements.json", gateAccountsJSON(gateUser, gatePassword, validUntil, grantedAt))

	// ---- 启动 proxy-server：accounts 模式 + 环回控制面 + 门禁开 ----
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
gate:
  enabled: true
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

	// gateClientConfig 生成一份开启门禁的客户端配置：http/socks5 入站强制
	// 认证（gate.enabled ⇒ 环回也不豁免）、entitlement 文件为订阅真相源、
	// 出口指向 nodeAddr（真实服务端或死端口）。
	gateClientConfig := func(name, nodeAddr string) string {
		return writeFile(t, dir, name, fmt.Sprintf(`
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
        - username: %s
          password: %s
  - type: socks5
    listen: "127.0.0.1:0"
    auth:
      users:
        - username: %s
          password: %s
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
gate:
  enabled: true
accounts:
  file: %q
`, gateUser, gatePassword, gateUser, gatePassword, nodeAddr, gatePassword, entitlementFile))
	}

	// ---- 阶段 1：有效订阅，门禁双侧开启，全链路放行 ----
	clientProc := startProcess(t, "proxy-client", filepath.Join(binDir, "proxy-client"),
		"-config", gateClientConfig("client-gate.yaml", tunnelAddr))
	clientListen := waitForRecords(t, clientProc, "listening", 1, 10*time.Second)[0]
	httpAddr := strField(t, clientProc, clientListen, "http")
	socks5Addr := strField(t, clientProc, clientListen, "socks5")
	waitForStatusOK(t, strField(t, clientProc, clientListen, "metrics"), 10*time.Second)

	// 黑盒证据：管理员分发的 entitlement 文件被加载为门禁视图。
	loaded := waitForRecords(t, clientProc, "entitlement file loaded", 1, 10*time.Second)[0]
	if got, ok := loaded["path"].(string); !ok || got != entitlementFile {
		t.Errorf("entitlement file loaded 记录 path = %v, want %q", loaded["path"], entitlementFile)
	}

	proxyURL, err := url.Parse("http://" + gateUser + ":" + gatePassword + "@" + httpAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	expectBody(t, newProxyClient(t, proxyURL), tlsTargetURL, "gate-ok")

	// SOCKS5 链路：static ∧ entitlement 复合认证通过 → 隧道 → 明文目标。
	socksConn := socks5Connect(t, socks5Addr, gateUser, gatePassword, plainTargetAddr)
	defer func() { _ = socksConn.Close() }()
	if _, err := fmt.Fprintf(socksConn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", plainTargetAddr); err != nil {
		t.Fatalf("socks5 write request: %v", err)
	}
	if got := readUntilEOF(t, socksConn, "socks5"); !strings.Contains(got, "gate-ok") {
		t.Fatalf("socks5 response = %q, want contain %q", got, "gate-ok")
	}
	_ = socksConn.Close()

	// 服务端证据：两条隧道由 accounts 用户完成（服务端门禁放行），allow 计数
	// 同步增长（计数器在组装根的隧道校验器处累计）。
	tunnelDone := waitForRecords(t, serverProc, "tunnel completed", 2, 10*time.Second)
	for _, rec := range tunnelDone {
		if got := strField(t, serverProc, rec, "user"); got != gateUser {
			t.Errorf("服务端隧道完成日志 user = %q, want %q（accounts 用户）", got, gateUser)
		}
	}
	waitForMetricSum(t, serverMetricsAddr, "entitlement_decisions_total",
		map[string]string{"decision": "allow", "reason": "none"}, 2)

	// ---- 阶段 2：到期 entitlement ⇒ 握手期拒绝，零拨号 ----
	// 对照组设计：clientDead 的唯一出口是一个无监听者的死端口。同一进程、
	// 同一死出口，唯一变量是订阅有效性：
	//   有效 entitlement：认证通过 → 尝试拨死出口 ⇒ 拨号类失败
	//                    （HTTP 502 / SOCKS5 CONNECT 阶段失败应答）；
	//   到期 entitlement：认证即拒 ⇒ HTTP 407 + 认证质询 /
	//                    SOCKS5 RFC 1929 认证阶段失败应答。
	// 失败类别翻转证明拒绝发生在握手期认证处，与出口可达性无关（零拨号）。
	deadProc := startProcess(t, "proxy-client-dead", filepath.Join(binDir, "proxy-client"),
		"-config", gateClientConfig("client-dead.yaml", deadNodeAddr))
	deadListen := waitForRecords(t, deadProc, "listening", 1, 10*time.Second)[0]
	deadHTTP := strField(t, deadProc, deadListen, "http")
	deadSocks5 := strField(t, deadProc, deadListen, "socks5")
	waitForStatusOK(t, strField(t, deadProc, deadListen, "metrics"), 10*time.Second)

	if got := gateConnectProbe(t, deadHTTP, gateUser, gatePassword, tlsTargetAddr); got.status != http.StatusBadGateway {
		t.Fatalf("对照（有效 entitlement + 死出口）CONNECT = %d, want 502（拨号类失败）", got.status)
	}
	if got := gateSocks5Probe(t, deadSocks5, gateUser, gatePassword, plainTargetAddr); !got.authOK || got.connectOK {
		t.Fatalf("对照（有效 entitlement + 死出口）SOCKS5 = %+v, want 认证通过 + CONNECT 阶段失败", got)
	}

	// 管理员重发到期 entitlement 文件（同一格式），SIGHUP 热加载生效。
	// 重载日志在监听重绑完成后打出（switchTo 提交 → OnReloaded），记录出现
	// 即新快照已在原端口服务（端口 0 的配置重载后保持原端口）。
	expiredUntil := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	writeFile(t, dir, "entitlements.json", gateAccountsJSON(gateUser, gatePassword, expiredUntil, grantedAt))
	if err := deadProc.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("signal proxy-client-dead SIGHUP: %v", err)
	}
	waitForRecords(t, deadProc, "configuration reloaded", 1, 10*time.Second)

	// HTTP：407 + 认证质询（非 502）——与对照同进程同死出口，失败类别翻转。
	if got := gateConnectProbe(t, deadHTTP, gateUser, gatePassword, tlsTargetAddr); got.status != http.StatusProxyAuthRequired {
		t.Fatalf("到期 entitlement 的 CONNECT = %d, want 407（认证层拒绝，非拨号失败）", got.status)
	} else if got.proxyAuthenticate == "" {
		t.Errorf("407 响应缺少 Proxy-Authenticate 质询头：%+v", got)
	}
	// SOCKS5：失败落在 RFC 1929 认证阶段（CONNECT 根本未发生）。
	if got := gateSocks5Probe(t, deadSocks5, gateUser, gatePassword, plainTargetAddr); got.authOK {
		t.Fatalf("到期 entitlement 的 SOCKS5 认证意外通过：%+v, want RFC 1929 认证阶段失败", got)
	}

	// ---- 阶段 3：服务端是防篡改的墙（§3.1）----
	// 控制面把订阅置为过去时刻（管理员纠错通道，含过去 = 即刻过期语义）。
	pastUntil := time.Now().Add(-time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	updated := controlRequest(t, controlAddr, http.MethodPut, "/users/"+gateUser+"/subscription",
		fmt.Sprintf(`{"expires_at":%q}`, pastUntil), http.StatusOK)
	if !strings.Contains(updated, pastUntil) {
		t.Errorf("PUT subscription 响应未回显到期时刻 %q：%s", pastUntil, updated)
	}

	// 非门禁客户端（用户手里的二进制可被篡改 ⇒ 本地无 gate 段，必然尝试隧道）。
	plainConfig := writeFile(t, dir, "client-plain.yaml", fmt.Sprintf(`
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
        - username: %s
          password: %s
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
`, plainClientUser, plainClientPassword, tunnelAddr, gatePassword))
	plainProc := startProcess(t, "proxy-client-plain", filepath.Join(binDir, "proxy-client"), "-config", plainConfig)
	plainListen := waitForRecords(t, plainProc, "listening", 1, 10*time.Second)[0]
	plainHTTP := strField(t, plainProc, plainListen, "http")
	waitForStatusOK(t, strField(t, plainProc, plainListen, "metrics"), 10*time.Second)

	// 到期用户的隧道被服务端拒绝：明文目标的响应是伪装页（不含目标内容）——
	// 被篡改的客户端拿不到数据，只拿到与普通 Web 服务无异的页面。
	decoyStatus, decoyBody := gateProxyGet(t, plainHTTP, plainClientUser, plainClientPassword, plainTargetURL)
	if decoyStatus != http.StatusOK || !strings.Contains(decoyBody, "<!DOCTYPE html>") || strings.Contains(decoyBody, "gate-ok") {
		t.Fatalf("到期用户经非门禁客户端的响应 = %d %q, want 200 伪装页（不含目标内容）", decoyStatus, decoyBody)
	}

	// I2 拒绝词汇统一：对 trojan 端口的原始握手上，到期口令摘要与未知口令
	// 摘要的线上响应逐字节同形（伪装页，不携带门禁原因细分）。
	decoy := trojanRawResponse(t, tunnelAddr, gatePassword, "localhost", uint16(plainTargetPort))
	unknown := trojanRawResponse(t, tunnelAddr, "no-such-user-password", "localhost", uint16(plainTargetPort))
	if !strings.Contains(decoy, "200 OK") || !strings.Contains(decoy, "<!DOCTYPE html>") {
		t.Errorf("到期用户的隧道原始响应不是伪装页：%q", decoy)
	}
	if decoy != unknown {
		t.Errorf("到期用户与认证失败的线上响应不同形：\n到期: %q\n未知: %q", decoy, unknown)
	}

	// 服务端黑盒证据：恰好 3 次隧道认证失败（非门禁客户端、到期原始握手、
	// 未知口令各一次），无新的隧道完成记录；deny:expired 决策计数在 /metrics
	// 可见（拒绝原因进指标与日志，不上协议线，§3.1）。
	if got := len(records(serverProc.logs, "tunnel authentication failed")); got != 3 {
		t.Errorf("tunnel authentication failed 记录 = %d, want 3（非门禁客户端、到期原始握手、未知口令各一次）", got)
	}
	if got := len(records(serverProc.logs, "tunnel completed")); got != 2 {
		t.Errorf("tunnel completed 记录 = %d, want 2（被拒隧道不得计入完成）", got)
	}
	waitForMetricSum(t, serverMetricsAddr, "entitlement_decisions_total",
		map[string]string{"decision": "deny", "reason": "expired"}, 2)

	// 管理员纠错（延长订阅到未来）⇒ 同一非门禁客户端零改动立即恢复——门禁
	// 与订阅状态都只在服务端，客户端侧不存在可篡改的放行开关。
	futureUntil := time.Now().Add(time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	controlRequest(t, controlAddr, http.MethodPut, "/users/"+gateUser+"/subscription",
		fmt.Sprintf(`{"expires_at":%q}`, futureUntil), http.StatusOK)
	recStatus, recBody := gateProxyGet(t, plainHTTP, plainClientUser, plainClientPassword, plainTargetURL)
	if recStatus != http.StatusOK || recBody != "gate-ok" {
		t.Fatalf("订阅恢复后的响应 = %d %q, want 200 %q（同一客户端，仅服务端订阅变更）", recStatus, recBody, "gate-ok")
	}
	// 恢复证据用门禁决策计数（VerifyTunnel 在隧道握手期累计）：tunnel completed
	// 记录在转发中继结束时才打——目标侧 keep-alive 连接存活期间隧道仍在服务，
	// 与本断言窗口无关；决策计数是即时信号。
	waitForMetricSum(t, serverMetricsAddr, "entitlement_decisions_total",
		map[string]string{"decision": "allow", "reason": "none"}, 3)

	// ---- 体面收尾：全部真实二进制优雅退出（与支付链路用例同一断言）----
	for _, p := range []*process{clientProc, deadProc, plainProc} {
		if err := p.terminate(t, 20*time.Second); err != nil {
			t.Fatalf("%s 退出: %v", p.name, err)
		}
	}
	if err := serverProc.terminate(t, 20*time.Second); err != nil {
		t.Fatalf("proxy-server 退出: %v", err)
	}
}

// —— 本文件的黑盒辅助（复用 integration_test.go / accounts_control_test.go /
// chaos_test.go 的脚手架）——

// gateAccountsJSON 生成账户库 / entitlement 文件内容（同一版本化 JSON 格式，
// 文件分发零转换）：单用户 + 完整订阅（到期与授予时刻都非零——存储期校验
// 要求成对出现，半写的订阅无法参与时钟回拨判定）。摘要由明文口令现算，
// 不 import internal/accounts（黑盒边界）。
func gateAccountsJSON(username, password string, expiresAt, grantedAt time.Time) string {
	sum256 := sha256.Sum256([]byte(password))
	sum224 := sha256.Sum224([]byte(password))
	return fmt.Sprintf(
		`{"version":1,"users":[{"username":%q,"password_sha256":%q,"password_sha224":%q,"status":"active","subscription":{"expires_at":%q,"granted_at":%q}}]}`,
		username, hex.EncodeToString(sum256[:]), hex.EncodeToString(sum224[:]),
		expiresAt.Format(time.RFC3339), grantedAt.Format(time.RFC3339))
}

// gateConnectResult 是一次 HTTP CONNECT 探测的线上结果。
type gateConnectResult struct {
	status            int
	proxyAuthenticate string
}

// gateConnectProbe 对 HTTP 入站发起一次 CONNECT（含代理认证），返回状态码与
// Proxy-Authenticate 头。零拨号论证的黑盒观测面：407 + 认证质询 = 握手期
// 认证拒绝；502 = 拨号期失败。手工编码以保持黑盒边界。
func gateConnectProbe(t *testing.T, proxyAddr, username, password, targetAddr string) gateConnectResult {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		targetAddr, targetAddr, auth)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("CONNECT write: %v", err)
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("CONNECT response: %v", err)
	}
	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(parts) < 2 {
		t.Fatalf("CONNECT status line = %q, want HTTP status line", strings.TrimSpace(statusLine))
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("parse CONNECT status %q: %v", strings.TrimSpace(statusLine), err)
	}
	result := gateConnectResult{status: code}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "Proxy-Authenticate") {
			result.proxyAuthenticate = strings.TrimSpace(value)
		}
	}
	return result
}

// gateSocks5ProbeResult 是一次 SOCKS5 握手探测的线上结果：RFC 1929 认证阶段
// 与 CONNECT 阶段分开记录。门禁拒绝复用认证拒绝通道（I2）⇒ 失败落在认证
// 阶段；拨号失败则认证通过、失败落在 CONNECT 阶段——阶段即零拨号证据。
type gateSocks5ProbeResult struct {
	authOK       bool
	connectOK    bool
	connectReply byte
}

// gateSocks5Probe 对 SOCKS5 入站做一次完整握手探测（手工编码，黑盒边界），
// 返回两阶段的应答结果，不在失败处中断测试（失败本身是被观测的行为）。
func gateSocks5Probe(t *testing.T, proxyAddr, username, password, targetAddr string) gateSocks5ProbeResult {
	t.Helper()
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target %q: %v", targetAddr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse target port %q: %v", portStr, err)
	}
	target, err := socks5EncodeTarget(host, uint16(port))
	if err != nil {
		t.Fatalf("encode target %q: %v", targetAddr, err)
	}

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("socks5 dial %s: %v", proxyAddr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 问候：只提供用户名/密码一种方法。
	if _, err := conn.Write([]byte{0x05, 1, 0x02}); err != nil {
		t.Fatalf("socks5 greeting: %v", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		t.Fatalf("socks5 method selection: %v", err)
	}
	if sel != [2]byte{0x05, 0x02} {
		// 服务器未选择用户名/密码方法 = 认证协商阶段失败。
		return gateSocks5ProbeResult{}
	}
	// RFC 1929 用户名/密码认证。
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("socks5 auth write: %v", err)
	}
	var authReply [2]byte
	if _, err := io.ReadFull(conn, authReply[:]); err != nil {
		t.Fatalf("socks5 auth reply: %v", err)
	}
	if authReply[0] != 0x01 || authReply[1] != 0x00 {
		return gateSocks5ProbeResult{} // 认证阶段拒绝（门禁拒绝走此通道）
	}
	// CONNECT 请求。
	req := append([]byte{0x05, 0x01, 0x00}, target...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("socks5 connect write: %v", err)
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		t.Fatalf("socks5 connect reply: %v", err)
	}
	return gateSocks5ProbeResult{authOK: true, connectOK: head[1] == 0x00, connectReply: head[1]}
}

// gateProxyGet 经代理 GET 一个明文 HTTP URL，返回状态码与响应体（观测伪装页
// 与目标内容的黑盒观测面）。
func gateProxyGet(t *testing.T, proxyAddr, username, password, rawURL string) (int, string) {
	t.Helper()
	proxyURL, err := url.Parse("http://" + username + ":" + password + "@" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s via proxy: %v", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: read body: %v", rawURL, err)
	}
	return resp.StatusCode, string(body)
}
