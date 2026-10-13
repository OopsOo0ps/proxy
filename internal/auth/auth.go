// Package auth 提供凭据存储与常量时间校验。
//
// 入站代理（HTTP / SOCKS5）使用用户名/密码校验；
// 隧道层（Trojan）只携带口令的 SHA-224 摘要，由摘要反查用户。
// 存储层保留口令摘要而非明文，降低内存泄露风险。
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// User 是一条用户名/密码凭据。
type User struct {
	Username string
	Password string
}

// SHA224Hex 返回口令的 SHA-224 十六进制小写摘要。
// 该格式与 Trojan 协议的口令行一致，客户端与服务端两侧共用。
func SHA224Hex(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
}

// Store 保存凭据，支持两种校验方式：
//   - Authenticate：入站代理的用户名/密码（HTTP Basic、SOCKS5 RFC 1929）；
//     方法名与 core.Authenticator 契约一致，实现方无需 import core；
//   - VerifyTunnel：隧道口令摘要（Trojan），返回匹配到的用户名
//
// Store 构造后只读，可安全并发使用。
type Store struct {
	inbound map[string][sha256.Size]byte
	tunnel  map[[sha256.Size224]byte]string
}

// NewStore 构建凭据存储；用户名或口令为空、重复用户名、
// 用户之间口令相同都会报错（隧道侧无法区分同口令用户）。
func NewStore(users []User) (*Store, error) {
	if len(users) == 0 {
		return nil, errors.New("auth: users must not be empty")
	}
	s := &Store{
		inbound: make(map[string][sha256.Size]byte, len(users)),
		tunnel:  make(map[[sha256.Size224]byte]string, len(users)),
	}
	for i, u := range users {
		if strings.TrimSpace(u.Username) == "" {
			return nil, fmt.Errorf("auth: users[%d]: username must not be empty", i)
		}
		if u.Password == "" {
			return nil, fmt.Errorf("auth: users[%d] (%s): password must not be empty", i, u.Username)
		}
		if strings.ContainsAny(u.Username+u.Password, "\r\n") {
			return nil, fmt.Errorf("auth: users[%d] (%s): username/password must not contain CR or LF", i, u.Username)
		}
		if _, dup := s.inbound[u.Username]; dup {
			return nil, fmt.Errorf("auth: duplicate username %q", u.Username)
		}
		s.inbound[u.Username] = sha256.Sum256([]byte(u.Password))

		var key [sha256.Size224]byte
		sum := sha256.Sum224([]byte(u.Password))
		copy(key[:], sum[:])
		if existing, dup := s.tunnel[key]; dup {
			return nil, fmt.Errorf("auth: users %q and %q must not share the same password", existing, u.Username)
		}
		s.tunnel[key] = u.Username
	}
	return s, nil
}

// Authenticate 以常量时间比较校验用户名/密码（core.Authenticator 契约实现）。
// 用户名不存在时同样执行一次摘要比较，避免通过响应时间枚举用户名。
func (s *Store) Authenticate(username, password string) bool {
	got := sha256.Sum256([]byte(password))
	// 未命中时 want 为零值摘要，比较依然执行，但不可能相等。
	want := s.inbound[username]
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// VerifyTunnel 校验 Trojan 口令摘要（十六进制，大小写均可），返回匹配的用户名。
// 遍历全部用户做常量时间比较，不因命中提前返回，避免时序侧信道。
func (s *Store) VerifyTunnel(hashHex string) (string, bool) {
	hashHex = strings.TrimSpace(hashHex)
	if len(hashHex) != sha256.Size224*2 {
		return "", false
	}
	raw, err := hex.DecodeString(hashHex)
	if err != nil || len(raw) != sha256.Size224 {
		return "", false
	}
	var key [sha256.Size224]byte
	copy(key[:], raw)

	matched, found := "", false
	for h, name := range s.tunnel {
		if subtle.ConstantTimeCompare(key[:], h[:]) == 1 {
			matched, found = name, true
		}
	}
	return matched, found
}

// Len 返回凭据条数。
func (s *Store) Len() int { return len(s.inbound) }
