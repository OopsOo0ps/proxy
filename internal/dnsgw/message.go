// DNS 报文的最小解析与错误响应构造。
//
// 网关只解析“头部 + 唯一问题段”用于分流决策，其余字节（如 EDNS0 OPT 记录）
// 原样转发给上游；构造错误响应时只回显头部（必要时附回问题段），不携带回答。
package dnsgw

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

const (
	// headerLen 是 DNS 头部长度（RFC 1035 4.1.1）。
	headerLen = 12

	flagQR = 0x8000 // 0 = 查询，1 = 响应
	flagTC = 0x0200 // 截断
	flagRA = 0x0080 // 服务器支持递归

	// RCODE（低 4 位）。
	rcodeFormatErr  = 1
	rcodeServerFail = 2
	rcodeRefused    = 5
)

// 解析错误分类：决定是否回错误响应以及回哪种。
var (
	errNotQuery         = errors.New("dns: message is a response, not a query")
	errBadOpcode        = errors.New("dns: unsupported opcode")
	errNoSingleQuestion = errors.New("dns: expected exactly one question")
	errMalformed        = errors.New("dns: malformed message")
)

// query 是解析后的 DNS 查询。
type query struct {
	payload     []byte // 原始查询报文（原样转发）
	id          uint16
	name        string // 归一化问题名（小写、无尾点）
	qtype       uint16
	questionEnd int // 问题段结束偏移，构造错误响应时用于回显问题段
}

// parseQuery 解析查询的头部与唯一问题段。
// 仅接受标准查询（QR=0、opcode=0、QDCOUNT=1）；其余返回对应的分类错误。
func parseQuery(payload []byte) (query, error) {
	q := query{payload: payload}
	if len(payload) < headerLen {
		return q, errMalformed
	}
	q.id = binary.BigEndian.Uint16(payload[0:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&flagQR != 0 {
		return q, errNotQuery
	}
	if opcode := (flags >> 11) & 0xF; opcode != 0 {
		return q, errBadOpcode
	}
	if qdcount := binary.BigEndian.Uint16(payload[4:6]); qdcount != 1 {
		return q, errNoSingleQuestion
	}
	name, off, err := parseName(payload, headerLen)
	if err != nil {
		return q, err
	}
	if len(payload) < off+4 {
		return q, errMalformed
	}
	q.name = name
	q.qtype = binary.BigEndian.Uint16(payload[off : off+2])
	q.questionEnd = off + 4
	return q, nil
}

// parseName 读取问题段中的域名，返回小写点分名字与结束偏移。
// 问题段不允许压缩指针（RFC 1035 4.1.4），遇到即视为非法报文。
func parseName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	total := 0
	for {
		if off >= len(msg) {
			return "", 0, errMalformed
		}
		n := int(msg[off])
		off++
		if n == 0 {
			return sb.String(), off, nil // 根（"."）返回空串
		}
		if n&0xC0 != 0 || n > 63 {
			return "", 0, errMalformed
		}
		if off+n > len(msg) {
			return "", 0, errMalformed
		}
		total += n + 1
		if total > 255 {
			return "", 0, errMalformed
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for _, b := range msg[off : off+n] {
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			sb.WriteByte(b)
		}
		off += n
	}
}

// errorResponse 构造不带问题段的错误响应（回显 ID 与标志位、清空各计数）。
// 载荷不足 2 字节（连 ID 都读不到）时返回 nil，由调用方静默丢弃。
func errorResponse(payload []byte, rcode uint16) []byte {
	if len(payload) < 2 {
		return nil
	}
	resp := make([]byte, headerLen)
	copy(resp, payload[:min(headerLen, len(payload))])
	resp = applyResponseFlags(resp, rcode)
	return resp
}

// errorResponseEcho 构造回显问题段的错误响应（SERVFAIL 等需要与查询
// 的问题段一致，否则严格的客户端会按无效响应丢弃）。
func errorResponseEcho(q query, rcode uint16) []byte {
	resp := make([]byte, headerLen, q.questionEnd)
	copy(resp, q.payload[:headerLen])
	resp = applyResponseFlags(resp, rcode)
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT
	resp = append(resp, q.payload[headerLen:q.questionEnd]...)
	return resp
}

// applyResponseFlags 设 QR=1、RA=1，清 TC/AA，写入 RCODE，并清零各段计数。
func applyResponseFlags(resp []byte, rcode uint16) []byte {
	flags := binary.BigEndian.Uint16(resp[2:4])
	flags |= flagQR | flagRA
	flags &^= flagTC | 0x0400 // 清 TC 与 AA（AA=0x0400）
	flags = flags&^0xF | rcode&0xF
	binary.BigEndian.PutUint16(resp[2:4], flags)
	for i := 4; i < headerLen; i += 2 { // QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT
		binary.BigEndian.PutUint16(resp[i:i+2], 0)
	}
	return resp
}

// validResponse 校验上游响应：长度足够、ID 与查询一致且为响应报文。
func validResponse(id uint16, msg []byte) bool {
	if len(msg) < headerLen {
		return false
	}
	if binary.BigEndian.Uint16(msg[0:2]) != id {
		return false
	}
	return binary.BigEndian.Uint16(msg[2:4])&flagQR != 0
}

// isTruncated 判断响应的 TC 位（UDP 截断时需按 RFC 1035 改走 TCP）。
func isTruncated(msg []byte) bool {
	if len(msg) < headerLen {
		return false
	}
	return binary.BigEndian.Uint16(msg[2:4])&flagTC != 0
}

// typeName 返回常见查询类型的可读名（未知类型返回 TYPE<n>）。
func typeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	default:
		return "TYPE" + strconv.Itoa(int(t))
	}
}
