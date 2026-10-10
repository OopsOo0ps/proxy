// Package trojan 实现 Trojan 协议（TLS 隧道）：客户端握手、服务端校验与转发。
//
// 线格式（与官方规范一致）：
//
//	hex(SHA224(password)) CRLF
//	CMD ATYP ADDR PORT CRLF
//	后续为原始载荷（握手成功后服务端不发送任何额外响应）
//
// 认证失败或非协议流量时，服务端返回伪装网页后关闭连接，
// 不在响应中泄露任何代理信息。
package trojan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/socks5"
)

// MaxHandshakeLine 限制握手行长度，防御恶意超长输入。
const MaxHandshakeLine = 512

var (
	errBadPasswordLine = errors.New("trojan: invalid password line")
	errBadTerminator   = errors.New("trojan: line must end with CRLF")
	errLineTooLong     = errors.New("trojan: handshake line too long")
)

// Request 是解析后的客户端握手。
type Request struct {
	// PasswordHash 是口令的 SHA-224 十六进制摘要。
	PasswordHash string
	// Command 与 SOCKS5 命令一致（CmdConnect / CmdUDPAssociate）。
	Command byte
	// Host、Port 是请求的目标地址。
	Host string
	Port uint16
}

// IsPasswordLineValid 判断密码行是否为合法的十六进制摘要（不校验具体口令）。
func IsPasswordLineValid(line string) bool {
	if len(line) != 56 {
		return false
	}
	for _, r := range line {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// IsNotProtocol 判断握手错误是否表示“非 Trojan 协议流量”
// （例如浏览器直接以 HTTPS 访问节点），用于决定伪装响应。
func IsNotProtocol(err error) bool {
	return errors.Is(err, errBadPasswordLine)
}

// WriteRequest 写出客户端握手。
func WriteRequest(w io.Writer, passwordHash, host string, port uint16) error {
	addr, err := socks5.EncodeAddr(host, port)
	if err != nil {
		return err
	}
	buf := make([]byte, 0, len(passwordHash)+2+1+len(addr)+2)
	buf = append(buf, passwordHash...)
	buf = append(buf, '\r', '\n', socks5.CmdConnect)
	buf = append(buf, addr...)
	buf = append(buf, '\r', '\n')
	_, err = w.Write(buf)
	return err
}

// ReadRequest 从 r 解析客户端握手（两行，均以 CRLF 结束）。
func ReadRequest(r *bufio.Reader) (Request, error) {
	req := Request{}
	passwordLine, err := readCRLFLine(r, MaxHandshakeLine)
	if err != nil {
		return req, fmt.Errorf("trojan: read password line: %w", err)
	}
	if !IsPasswordLineValid(passwordLine) {
		return req, errBadPasswordLine
	}
	req.PasswordHash = strings.ToLower(passwordLine)

	requestLine, err := readCRLFLine(r, MaxHandshakeLine)
	if err != nil {
		return req, fmt.Errorf("trojan: read request line: %w", err)
	}
	if len(requestLine) < 2 {
		return req, errors.New("trojan: request line too short")
	}
	req.Command = requestLine[0]
	host, port, err := socks5.DecodeAddr(bytes.NewReader([]byte(requestLine[1:])))
	if err != nil {
		return req, fmt.Errorf("trojan: decode target: %w", err)
	}
	req.Host, req.Port = host, port
	return req, nil
}

// readCRLFLine 读取一行（以 CRLF 结束，不含 CRLF），超过 max 长度报错。
func readCRLFLine(r *bufio.Reader, max int) (string, error) {
	var buf []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			if len(buf) == 0 || buf[len(buf)-1] != '\r' {
				return "", errBadTerminator
			}
			return string(buf[:len(buf)-1]), nil
		}
		buf = append(buf, b)
		if len(buf) > max {
			return "", errLineTooLong
		}
	}
}

// ClientConfig 描述连接一个出口节点所需的参数。
type ClientConfig struct {
	// ServerAddr 是节点地址（host:port）。
	ServerAddr string
	// Password 是隧道口令。
	Password string
	// TLSConfig 是 TLS 参数；ServerName 为空时使用 ServerAddr 的主机名。
	TLSConfig *tls.Config
	// DialTimeout 是 TCP 连接超时，默认 10s。
	DialTimeout time.Duration
	// HandshakeTimeout 是 TLS 握手与请求写入超时，默认 10s。
	HandshakeTimeout time.Duration
}

// Dial 建立到出口节点的 TLS 隧道，并向 target(host, port) 发起 Trojan 请求。
// 返回的连接已就绪，可直接转发目标协议的原始字节。
func Dial(ctx context.Context, cfg ClientConfig, host string, port uint16) (net.Conn, error) {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}

	d := &net.Dialer{Timeout: cfg.DialTimeout}
	raw, err := d.DialContext(ctx, "tcp", cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("trojan: dial node %s: %w", cfg.ServerAddr, err)
	}

	tlsCfg := cfg.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if tlsCfg.ServerName == "" {
		if hostPart, _, err := net.SplitHostPort(cfg.ServerAddr); err == nil {
			tlsCfg = tlsCfg.Clone()
			tlsCfg.ServerName = hostPart
		}
	}

	tconn := tls.Client(raw, tlsCfg)
	handshakeCtx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()
	if err := tconn.HandshakeContext(handshakeCtx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("trojan: tls handshake with %s: %w", cfg.ServerAddr, err)
	}

	_ = tconn.SetWriteDeadline(time.Now().Add(cfg.HandshakeTimeout))
	if err := WriteRequest(tconn, auth.SHA224Hex(cfg.Password), host, port); err != nil {
		_ = tconn.Close()
		return nil, fmt.Errorf("trojan: write request to %s: %w", cfg.ServerAddr, err)
	}
	_ = tconn.SetDeadline(time.Time{})
	return tconn, nil
}
