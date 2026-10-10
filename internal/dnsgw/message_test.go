package dnsgw

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/OopsOo0ps/proxy/internal/testutil"
)

func TestParseQueryValid(t *testing.T) {
	payload := testutil.BuildAQuery("Example.COM", 0x1234)
	q, err := parseQuery(payload)
	if err != nil {
		t.Fatalf("parseQuery: %v", err)
	}
	if q.id != 0x1234 {
		t.Fatalf("id = %#x, want 0x1234", q.id)
	}
	if q.name != "example.com" {
		t.Fatalf("name = %q, want example.com（应统一小写）", q.name)
	}
	if q.qtype != 1 {
		t.Fatalf("qtype = %d, want 1 (A)", q.qtype)
	}
	if q.questionEnd != len(payload) {
		t.Fatalf("questionEnd = %d, want %d", q.questionEnd, len(payload))
	}
}

func TestParseQueryRejects(t *testing.T) {
	valid := testutil.BuildAQuery("example.com", 1)
	mutate := func(f func([]byte) []byte) []byte {
		cp := make([]byte, len(valid))
		copy(cp, valid)
		return f(cp)
	}
	// 问题段带压缩指针的报文：头部 + 0xC0 0x0C + 类型/类。
	pointer := append(append([]byte{}, valid[:12]...), 0xC0, 0x0C, 0, 1, 0, 1)
	// 超长 label（0x40 = 64）。
	longLabel := append(append([]byte{}, valid[:12]...), 0x40, 'a', 0, 0, 1, 0, 1)

	cases := map[string]struct {
		payload []byte
		want    error
	}{
		"short header":       {valid[:8], errMalformed},
		"truncated question": {valid[:len(valid)-3], errMalformed},
		"pointer in name":    {pointer, errMalformed},
		"label too long":     {longLabel, errMalformed},
		"not a query":        {mutate(func(b []byte) []byte { b[2] |= 0x80; return b }), errNotQuery},
		"bad opcode":         {mutate(func(b []byte) []byte { b[2] |= 5 << 3; return b }), errBadOpcode},
		"no question":        {mutate(func(b []byte) []byte { binary.BigEndian.PutUint16(b[4:6], 0); return b }), errNoSingleQuestion},
		"two questions":      {mutate(func(b []byte) []byte { binary.BigEndian.PutUint16(b[4:6], 2); return b }), errNoSingleQuestion},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseQuery(tc.payload); !errors.Is(err, tc.want) {
				t.Fatalf("parseQuery error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestErrorResponseEchoesQuestion(t *testing.T) {
	payload := testutil.BuildAQuery("fail.test", 0x0102)
	q, err := parseQuery(payload)
	if err != nil {
		t.Fatal(err)
	}
	resp := errorResponseEcho(q, rcodeServerFail)
	if got := testutil.DNSID(resp); got != 0x0102 {
		t.Fatalf("id = %#x, want 0x0102", got)
	}
	if got := testutil.DNSRcode(resp); got != rcodeServerFail {
		t.Fatalf("rcode = %d, want %d", got, rcodeServerFail)
	}
	if flags := binary.BigEndian.Uint16(resp[2:4]); flags&flagQR == 0 || flags&flagRA == 0 {
		t.Fatalf("flags = %#x, want QR and RA set", flags)
	}
	if qdcount := binary.BigEndian.Uint16(resp[4:6]); qdcount != 1 {
		t.Fatalf("qdcount = %d, want 1", qdcount)
	}
	if name := testutil.DNSQuestionName(resp); name != "fail.test" {
		t.Fatalf("question name = %q, want fail.test", name)
	}
}

func TestErrorResponseWithoutQuestion(t *testing.T) {
	resp := errorResponse(testutil.BuildAQuery("x.test", 7), rcodeFormatErr)
	if got := testutil.DNSID(resp); got != 7 {
		t.Fatalf("id = %d, want 7", got)
	}
	if got := testutil.DNSRcode(resp); got != rcodeFormatErr {
		t.Fatalf("rcode = %d, want %d", got, rcodeFormatErr)
	}
	if len(resp) != 12 {
		t.Fatalf("len = %d, want 12（不回显问题段）", len(resp))
	}
	if qdcount := binary.BigEndian.Uint16(resp[4:6]); qdcount != 0 {
		t.Fatalf("qdcount = %d, want 0", qdcount)
	}
}

func TestErrorResponseShortPayload(t *testing.T) {
	if resp := errorResponse([]byte{0x01}, rcodeFormatErr); resp != nil {
		t.Fatalf("payload 不足 2 字节应返回 nil，得到 %v", resp)
	}
	resp := errorResponse([]byte{0x12, 0x34, 0x01}, rcodeFormatErr)
	if resp == nil || testutil.DNSID(resp) != 0x1234 {
		t.Fatalf("resp = %v, want 12 字节响应且保留 ID", resp)
	}
}

func TestValidResponseAndTruncation(t *testing.T) {
	reply := testutil.BuildReply(testutil.BuildAQuery("a.test", 0x55), 0, nil, false)
	if !validResponse(0x55, reply) {
		t.Fatal("validResponse = false, want true")
	}
	if validResponse(0x56, reply) {
		t.Fatal("validResponse 对 ID 不匹配应返回 false")
	}
	if validResponse(0x55, testutil.BuildAQuery("a.test", 0x55)) {
		t.Fatal("validResponse 对查询报文应返回 false")
	}
	if isTruncated(reply) {
		t.Fatal("isTruncated = true, want false")
	}
	truncated := testutil.BuildReply(testutil.BuildAQuery("a.test", 0x55), 0, nil, true)
	if !isTruncated(truncated) {
		t.Fatal("isTruncated = false, want true")
	}
}
