package testutil

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DNS 测试辅助：构造 / 解析 DNS 报文与一个最小的测试解析器（UDP + TCP）。
// 仅供测试使用；解析实现对标准查询足够，不追求完备。

// BuildAQuery 构造一条 QTYPE=A 的标准查询报文。
func BuildAQuery(name string, id uint16) []byte {
	name = strings.TrimSuffix(name, ".")
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], id)
	buf[2] = 0x01 // RD
	binary.BigEndian.PutUint16(buf[4:6], 1)
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
		}
	}
	buf = append(buf, 0)    // 名字结束
	buf = append(buf, 0, 1) // QTYPE = A
	buf = append(buf, 0, 1) // QCLASS = IN
	return buf
}

// BuildReply 由查询构造响应：回显问题段，按需附加 A/AAAA 记录；
// tc 置截断位，rcode 写入响应码。
func BuildReply(query []byte, rcode int, ips []netip.Addr, tc bool) []byte {
	end := queryQuestionEnd(query)
	if end < 0 {
		return nil
	}
	resp := make([]byte, 12)
	copy(resp, query[:12])
	flags := binary.BigEndian.Uint16(resp[2:4])
	flags |= 0x8000 | 0x0080 // QR=1, RA=1
	if tc {
		flags |= 0x0200
	}
	flags = flags&^0xF | uint16(rcode)&0xF
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(ips)))
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	resp = append(resp, query[12:end]...)
	for _, ip := range ips {
		resp = appendAnswer(resp, ip)
	}
	return resp
}

func appendAnswer(buf []byte, ip netip.Addr) []byte {
	buf = append(buf, 0xC0, 0x0C) // 指向问题段的名字（偏移 12）
	if ip.Is4() {
		raw := ip.As4()
		buf = append(buf, 0, 1, 0, 1)  // TYPE=A, CLASS=IN
		buf = append(buf, 0, 0, 0, 60) // TTL=60
		buf = append(buf, 0, 4)        // RDLENGTH
		return append(buf, raw[:]...)
	}
	raw := ip.As16()
	buf = append(buf, 0, 28, 0, 1) // TYPE=AAAA, CLASS=IN
	buf = append(buf, 0, 0, 0, 60) // TTL=60
	buf = append(buf, 0, 16)       // RDLENGTH
	return append(buf, raw[:]...)
}

// queryQuestionEnd 返回查询报文问题段的结束偏移（不解引用压缩指针）。
func queryQuestionEnd(msg []byte) int {
	if len(msg) < 12 {
		return -1
	}
	off := skipName(msg, 12)
	if off < 0 || off+4 > len(msg) {
		return -1
	}
	return off + 4
}

func skipName(msg []byte, off int) int {
	for off < len(msg) {
		n := int(msg[off])
		if n == 0 {
			return off + 1
		}
		if n&0xC0 == 0xC0 {
			return off + 2
		}
		off += n + 1
	}
	return -1
}

// DNSID 返回报文 ID（不足 2 字节时返回 0）。
func DNSID(msg []byte) uint16 {
	if len(msg) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(msg[0:2])
}

// DNSRcode 返回响应码（报文过短时返回 -1）。
func DNSRcode(msg []byte) int {
	if len(msg) < 4 {
		return -1
	}
	return int(msg[3] & 0xF)
}

// DNSQuestionName 返回报文问题段的原始名字（未做小写归一化）。
func DNSQuestionName(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	var sb strings.Builder
	off := 12
	for off < len(msg) {
		n := int(msg[off])
		if n == 0 {
			return sb.String()
		}
		if n&0xC0 != 0 || off+1+n > len(msg) {
			return ""
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(msg[off+1 : off+1+n])
		off += n + 1
	}
	return ""
}

// DNSAnswerIPs 返回响应中的 A/AAAA 记录地址（按出现顺序）。
func DNSAnswerIPs(msg []byte) []netip.Addr {
	if len(msg) < 12 {
		return nil
	}
	off := 12
	for i := int(binary.BigEndian.Uint16(msg[4:6])); i > 0; i-- {
		off = skipName(msg, off)
		if off < 0 || off+4 > len(msg) {
			return nil
		}
		off += 4
	}
	var out []netip.Addr
	for i := int(binary.BigEndian.Uint16(msg[6:8])); i > 0; i-- {
		off = skipName(msg, off)
		if off < 0 || off+10 > len(msg) {
			return out
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return out
		}
		switch {
		case typ == 1 && rdlen == 4:
			out = append(out, netip.AddrFrom4([4]byte(msg[off:off+4])))
		case typ == 28 && rdlen == 16:
			out = append(out, netip.AddrFrom16([16]byte(msg[off:off+16])))
		}
		off += rdlen
	}
	return out
}

// WriteDNSFrame 写出 DNS over TCP 长度前缀帧（单次写出，避免 Nagle 分段）。
func WriteDNSFrame(w io.Writer, payload []byte) error {
	if len(payload) > 0xFFFF {
		return errors.New("testutil: payload too large")
	}
	buf := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(payload)))
	copy(buf[2:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadDNSFrame 读取 DNS over TCP 长度前缀帧。
func ReadDNSFrame(r io.Reader) ([]byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(head[:]))
	if n == 0 {
		return nil, errors.New("testutil: empty frame")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// DNSHandler 处理一条查询并返回响应；返回 nil 表示不响应。
type DNSHandler func(query []byte, network string) []byte

// DNSServer 是测试用的最小 DNS 解析器（UDP + TCP 同端口）。
type DNSServer struct {
	// Addr 是 UDP/TCP 共用的监听地址。
	Addr string

	handler  DNSHandler
	udpConn  *net.UDPConn
	tcpLn    net.Listener
	udpHits  atomic.Int64
	tcpHits  atomic.Int64
	wg       sync.WaitGroup
	conns    sync.WaitGroup
	closeOne sync.Once
}

// StartDNSServer 在环回地址上启动测试解析器。
func StartDNSServer(handler DNSHandler) (*DNSServer, error) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", tcpLn.Addr().String())
	if err != nil {
		_ = tcpLn.Close()
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_ = tcpLn.Close()
		return nil, err
	}
	s := &DNSServer{Addr: tcpLn.Addr().String(), handler: handler, udpConn: udpConn, tcpLn: tcpLn}
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	return s, nil
}

func (s *DNSServer) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, from, err := s.udpConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		s.udpHits.Add(1)
		query := make([]byte, n)
		copy(query, buf[:n])
		if resp := s.handler(query, "udp"); resp != nil {
			_ = s.udpConn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = s.udpConn.WriteToUDPAddrPort(resp, from)
		}
	}
}

func (s *DNSServer) serveTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			return
		}
		s.conns.Add(1)
		go func() {
			defer s.conns.Done()
			defer func() { _ = conn.Close() }()
			for {
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				query, err := ReadDNSFrame(conn)
				if err != nil {
					return
				}
				s.tcpHits.Add(1)
				resp := s.handler(query, "tcp")
				if resp == nil {
					return
				}
				_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
				if err := WriteDNSFrame(conn, resp); err != nil {
					return
				}
			}
		}()
	}
}

// UDPHits 返回 UDP 查询数。
func (s *DNSServer) UDPHits() int64 { return s.udpHits.Load() }

// TCPHits 返回 TCP 查询数。
func (s *DNSServer) TCPHits() int64 { return s.tcpHits.Load() }

// Close 停止解析器。
func (s *DNSServer) Close() {
	s.closeOne.Do(func() {
		_ = s.udpConn.Close()
		_ = s.tcpLn.Close()
	})
	done := make(chan struct{})
	go func() {
		s.wg.Wait() // 监听循环退出后不再有新的连接计数
		s.conns.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

// QueryUDP 向 addr 发送查询并等待响应（超时返回错误）。
// 读缓冲固定 4096；需要接收更大的响应时使用 QueryUDPWithBuffer。
func QueryUDP(addr string, query []byte, timeout time.Duration) ([]byte, error) {
	return QueryUDPWithBuffer(addr, query, 4096, timeout)
}

// QueryUDPWithBuffer 向 addr 发送查询并等待响应，读缓冲为 bufSize
// （QueryUDP 的可定制版本，机械完全一致）。
func QueryUDPWithBuffer(addr string, query []byte, bufSize int, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, bufSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
