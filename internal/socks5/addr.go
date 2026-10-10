// Package socks5 实现 SOCKS5 入站代理（RFC 1928 / RFC 1929）与地址编码。
//
// 地址编码（ATYP + ADDR + PORT）为 SOCKS5 与 Trojan 协议共用。
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// SOCKS5 常量。
const (
	Version = 0x05

	// 认证方法（RFC 1928 第 3 节）。
	MethodNoAuth       = 0x00
	MethodUserPass     = 0x02
	MethodNoAcceptable = 0xFF

	// 用户名/密码子协商（RFC 1929）。
	UserPassVersion    = 0x01
	UserPassStatusOK   = 0x00
	UserPassStatusFail = 0x01

	// 命令。
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	// 回复码。
	ReplySuccess         = 0x00
	ReplyGeneralFailure  = 0x01
	ReplyConnRefused     = 0x05
	ReplyCmdNotSupported = 0x07

	// 地址类型。
	ATYPIPv4   = 0x01
	ATYPDomain = 0x03
	ATYPIPv6   = 0x04
)

// EncodeAddr 按 SOCKS5 地址格式编码 host:port。
func EncodeAddr(host string, port uint16) ([]byte, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			raw := ip.As4()
			buf := make([]byte, 0, 1+4+2)
			buf = append(buf, ATYPIPv4)
			buf = append(buf, raw[:]...)
			return appendPort(buf, port), nil
		}
		raw := ip.As16()
		buf := make([]byte, 0, 1+16+2)
		buf = append(buf, ATYPIPv6)
		buf = append(buf, raw[:]...)
		return appendPort(buf, port), nil
	}
	if host == "" || len(host) > 255 {
		return nil, fmt.Errorf("socks5: invalid host %q", host)
	}
	buf := make([]byte, 0, 2+len(host)+2)
	buf = append(buf, ATYPDomain, byte(len(host)))
	buf = append(buf, host...)
	return appendPort(buf, port), nil
}

func appendPort(buf []byte, port uint16) []byte {
	return append(buf, byte(port>>8), byte(port))
}

// DecodeAddr 从 r 读取一个 SOCKS5 地址，返回主机（IPv6 不带方括号）与端口。
func DecodeAddr(r io.Reader) (string, uint16, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, fmt.Errorf("socks5: read address type: %w", err)
	}

	var host string
	switch atyp[0] {
	case ATYPIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return "", 0, fmt.Errorf("socks5: read ipv4 address: %w", err)
		}
		host = netip.AddrFrom4(raw).String()
	case ATYPIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return "", 0, fmt.Errorf("socks5: read ipv6 address: %w", err)
		}
		host = netip.AddrFrom16(raw).String()
	case ATYPDomain:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", 0, fmt.Errorf("socks5: read domain length: %w", err)
		}
		if length[0] == 0 {
			return "", 0, errors.New("socks5: empty domain")
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, raw); err != nil {
			return "", 0, fmt.Errorf("socks5: read domain: %w", err)
		}
		host = string(raw)
	default:
		return "", 0, fmt.Errorf("socks5: unsupported address type %#x", atyp[0])
	}

	var portRaw [2]byte
	if _, err := io.ReadFull(r, portRaw[:]); err != nil {
		return "", 0, fmt.Errorf("socks5: read port: %w", err)
	}
	return host, binary.BigEndian.Uint16(portRaw[:]), nil
}
