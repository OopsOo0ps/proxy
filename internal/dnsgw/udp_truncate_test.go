// P2-9：UDP 大响应中继与写回侧截断语义的回归测试。
//
// 覆盖三块行为：
//  1. 上游 UDP 响应超过旧读缓冲 4096 时完整中继（读侧不再静默截断）；
//  2. 上游响应超出客户端声明上限（无 OPT → 512）时回 TC=1 最小响应；
//  3. 写回截断的严格边界：len(resp) == udpLimit 不截断，超过 1 字节即截断。
package dnsgw

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/testutil"
)

// appendOPT 在查询报文后附加一条 EDNS0 OPT 记录（CLASS = udpLimit，即
// RFC 6891 §6.2.3 的客户端 UDP 声明值）并把 ARCOUNT 置 1。
func appendOPT(query []byte, udpLimit uint16) []byte {
	opt := []byte{
		0x00,       // NAME：根
		0x00, 0x29, // TYPE = OPT(41)
		byte(udpLimit >> 8), byte(udpLimit), // CLASS：声明上限
		0x00, 0x00, 0x00, 0x00, // TTL（扩展 RCODE / 标志）
		0x00, 0x00, // RDLENGTH = 0
	}
	out := append(query, opt...)
	binary.BigEndian.PutUint16(out[10:12], 1) // ARCOUNT
	return out
}

// wireNameLen 返回名字在报文中的线格式长度（根字节 + 每标签的长度字节）。
func wireNameLen(name string) int {
	n := 1 // 根
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		n += 1 + len(label)
	}
	return n
}

// aReplyRecords 计算使响应恰为 want 字节所需的 A 记录数（每条 A 记录
// 16 字节：压缩指针 2 + 固定 10 + RDATA 4）。无法整除时测试直接失败。
func aReplyRecords(t *testing.T, name string, want int) int {
	t.Helper()
	base := 12 + wireNameLen(name) + 4
	if (want-base)%16 != 0 {
		t.Fatalf("name %q cannot build a %d-byte reply (base=%d)", name, want, base)
	}
	return (want - base) / 16
}

// manyIPs 生成 n 个互不相同的测试地址。
func manyIPs(n int) []netip.Addr {
	ips := make([]netip.Addr, n)
	for i := range ips {
		ips[i] = netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
	}
	return ips
}

func startSizedLocalResolver(t *testing.T, name string, records int) *testutil.DNSServer {
	t.Helper()
	local, err := testutil.StartDNSServer(func(q []byte, network string) []byte {
		if network != "udp" {
			t.Errorf("local resolver queried over %s, want udp", network)
		}
		return testutil.BuildReply(q, 0, manyIPs(records), false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)
	return local
}

func startTruncateTestGateway(t *testing.T, localAddr string) *gatewayHandle {
	t.Helper()
	return startGateway(t, Options{
		Local:   []string{localAddr},
		Timeout: 3 * time.Second,
		Direct:  dialDirectUDP(),
		Proxy:   noDial("tunnel must not be used for direct names"),
	})
}

// TestUDPLargeUpstreamResponseRelayedIntact 钉住读侧语义：上游 UDP 回
// ~5000B 的合法响应（> 旧读缓冲 4096）时，客户端声明的上限足够大即完整
// 收到；声明 4096 时则按客户端上限写回 TC 截断（不再静默裁剪）。
func TestUDPLargeUpstreamResponseRelayedIntact(t *testing.T) {
	// "big.lan"：问题段前缀 25 字节，310 条 A 记录 → 4985B。
	const bigName = "big.lan"
	local := startSizedLocalResolver(t, bigName, aReplyRecords(t, bigName, 4985))
	gw := startTruncateTestGateway(t, local.Addr)

	t.Run("declared above response size", func(t *testing.T) {
		query := appendOPT(testutil.BuildAQuery(bigName, 0x0901), 8192)
		resp, err := testutil.QueryUDPWithBuffer(gw.addr, query, 8192, 3*time.Second)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if got := testutil.DNSID(resp); got != 0x0901 {
			t.Fatalf("id = %#x, want 0x901", got)
		}
		if len(resp) <= 4096 {
			t.Fatalf("response len = %d, want > 4096（读侧不得静默截断）", len(resp))
		}
		if isTruncated(resp) {
			t.Fatal("response is truncated, want intact")
		}
		if got := len(testutil.DNSAnswerIPs(resp)); got != 310 {
			t.Fatalf("answers = %d, want 310", got)
		}
	})

	t.Run("declared 4096 below response size", func(t *testing.T) {
		query := appendOPT(testutil.BuildAQuery(bigName, 0x0902), 4096)
		resp, err := testutil.QueryUDPWithBuffer(gw.addr, query, 8192, 3*time.Second)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if !isTruncated(resp) {
			t.Fatalf("response len = %d, want TC=1（超出声明上限必须显式截断）", len(resp))
		}
		if got := binary.BigEndian.Uint16(resp[6:8]); got != 0 {
			t.Fatalf("ancount = %d, want 0", got)
		}
		if got := binary.BigEndian.Uint16(resp[10:12]); got != 0 {
			t.Fatalf("arcount = %d, want 0（TC 响应不放 OPT）", got)
		}
		if name := testutil.DNSQuestionName(resp); name != bigName {
			t.Fatalf("question name = %q, want %q", name, bigName)
		}
	})
}

// TestUDPWriteBackTruncatedToClientLimit 钉住写回侧截断：查询未携带 EDNS0
// （上限 512），上游回 ~800B → 客户端收到 ≤512B 的 TC=1 最小响应，
// RCODE 不破坏、ANCOUNT=0、问题段与查询一致。
func TestUDPWriteBackTruncatedToClientLimit(t *testing.T) {
	// "trunc.lan"：问题段前缀 27 字节，50 条 A 记录 → 827B。
	const truncName = "trunc.lan"
	local := startSizedLocalResolver(t, truncName, aReplyRecords(t, truncName, 827))
	gw := startTruncateTestGateway(t, local.Addr)

	query := testutil.BuildAQuery(truncName, 0x0a01) // 无 EDNS0 → 上限 512
	resp, err := testutil.QueryUDPWithBuffer(gw.addr, query, 4096, 3*time.Second)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(resp) > 512 {
		t.Fatalf("response len = %d, want <= 512", len(resp))
	}
	if !isTruncated(resp) {
		t.Fatal("response is not truncated, want TC=1")
	}
	if got := testutil.DNSID(resp); got != 0x0a01 {
		t.Fatalf("id = %#x, want 0xa01", got)
	}
	if got := testutil.DNSRcode(resp); got != 0 {
		t.Fatalf("rcode = %d, want 0（截断不得破坏 RCODE）", got)
	}
	if got := binary.BigEndian.Uint16(resp[6:8]); got != 0 {
		t.Fatalf("ancount = %d, want 0", got)
	}
	if name := testutil.DNSQuestionName(resp); name != truncName {
		t.Fatalf("question name = %q, want %q（问题段需与查询一致）", name, truncName)
	}
}

// TestUDPWriteBackBoundary 钉住截断判定的严格边界：
// len(resp) == udpLimit 不截断（原样回全量），超出 1 字节即 TC 截断。
func TestUDPWriteBackBoundary(t *testing.T) {
	// 问题段前缀分别 33B / 32B，使响应恰为 1233B / 4096B。
	const name1233 = "abcdef12345.lan" // wireName 17 → base 33，75 条 A 记录
	const name4096 = "abcdef1234.lan"  // wireName 16 → base 32，254 条 A 记录
	recs1233 := aReplyRecords(t, name1233, 1233)
	recs4096 := aReplyRecords(t, name4096, 4096)

	local, err := testutil.StartDNSServer(func(q []byte, network string) []byte {
		if network != "udp" {
			t.Errorf("local resolver queried over %s, want udp", network)
		}
		switch testutil.DNSQuestionName(q) {
		case name1233:
			return testutil.BuildReply(q, 0, manyIPs(recs1233), false)
		case name4096:
			return testutil.BuildReply(q, 0, manyIPs(recs4096), false)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)
	gw := startTruncateTestGateway(t, local.Addr)

	t.Run("declared 1232 upstream 1233 truncated", func(t *testing.T) {
		query := appendOPT(testutil.BuildAQuery(name1233, 0x0b01), 1232)
		resp, err := testutil.QueryUDPWithBuffer(gw.addr, query, 4096, 3*time.Second)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if !isTruncated(resp) {
			t.Fatalf("response len = %d, want TC=1（超出 1 字节也须显式截断）", len(resp))
		}
		if got := binary.BigEndian.Uint16(resp[6:8]); got != 0 {
			t.Fatalf("ancount = %d, want 0", got)
		}
		if name := testutil.DNSQuestionName(resp); name != name1233 {
			t.Fatalf("question name = %q, want %q", name, name1233)
		}
	})

	t.Run("declared 1233 upstream 1233 intact", func(t *testing.T) {
		query := appendOPT(testutil.BuildAQuery(name1233, 0x0b02), 1233)
		resp, err := testutil.QueryUDPWithBuffer(gw.addr, query, 4096, 3*time.Second)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if isTruncated(resp) {
			t.Fatal("response is truncated at exactly the declared limit, want intact")
		}
		if len(resp) != 1233 {
			t.Fatalf("response len = %d, want 1233", len(resp))
		}
	})

	t.Run("declared 4096 upstream 4096 intact", func(t *testing.T) {
		query := appendOPT(testutil.BuildAQuery(name4096, 0x0b03), 4096)
		resp, err := testutil.QueryUDPWithBuffer(gw.addr, query, 8192, 3*time.Second)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if isTruncated(resp) {
			t.Fatal("response is truncated at exactly the declared limit, want intact")
		}
		if len(resp) != 4096 {
			t.Fatalf("response len = %d, want 4096", len(resp))
		}
		if got := len(testutil.DNSAnswerIPs(resp)); got != recs4096 {
			t.Fatalf("answers = %d, want %d", got, recs4096)
		}
	})
}

// TestParseQueryEDNS0UDPLimit 钉住 OPT 解析规则：声明合法用声明值，
// 无 OPT / 无附加区 / 声明 <512 / 附加区畸形 → 512；查询合法性不受附加区
// 畸形影响（errMalformed 路径不变）。
func TestParseQueryEDNS0UDPLimit(t *testing.T) {
	base := testutil.BuildAQuery("x.lan", 0x0c01)

	if q, err := parseQuery(base); err != nil || q.udpLimit != 512 {
		t.Fatalf("no OPT: udpLimit = %d err = %v, want 512 / nil", q.udpLimit, err)
	}
	if q, err := parseQuery(appendOPT(base, 1232)); err != nil || q.udpLimit != 1232 {
		t.Fatalf("declared 1232: udpLimit = %d err = %v, want 1232 / nil", q.udpLimit, err)
	}
	if q, err := parseQuery(appendOPT(base, 65535)); err != nil || q.udpLimit != 65535 {
		t.Fatalf("declared 65535: udpLimit = %d err = %v, want 65535 / nil", q.udpLimit, err)
	}
	// 声明 <512（如 0、100）→ 缺省 512。
	for _, declared := range []uint16{0, 100, 511} {
		if q, err := parseQuery(appendOPT(base, declared)); err != nil || q.udpLimit != 512 {
			t.Fatalf("declared %d: udpLimit = %d err = %v, want 512 / nil", declared, q.udpLimit, err)
		}
	}
	// ARCOUNT=1 但附加的是非 OPT 记录（TYPE=A）→ 512。
	nonOPT := append([]byte{}, base...)
	nonOPT = append(nonOPT,
		0x00,       // NAME：根
		0x00, 0x01, // TYPE = A
		0x00, 0x01, // CLASS = IN
		0x00, 0x00, 0x00, 0x00, // TTL
		0x00, 0x04, // RDLENGTH
		1, 2, 3, 4, // RDATA
	)
	binary.BigEndian.PutUint16(nonOPT[10:12], 1)
	if q, err := parseQuery(nonOPT); err != nil || q.udpLimit != 512 {
		t.Fatalf("non-OPT additional RR: udpLimit = %d err = %v, want 512 / nil", q.udpLimit, err)
	}
	// 附加区被截断（OPT 声明不完整）：查询本身仍合法，按 512 处理。
	clipped := appendOPT(base, 4096)[:len(base)+6]
	if q, err := parseQuery(clipped); err != nil || q.udpLimit != 512 {
		t.Fatalf("clipped OPT: udpLimit = %d err = %v, want 512 / nil", q.udpLimit, err)
	}
}
