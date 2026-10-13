package auth

import (
	"fmt"
	"strings"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore([]User{
		{Username: "alice", Password: "alice-secret"},
		{Username: "bob", Password: "bob-secret"},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func TestNewStoreRejectsInvalidUsers(t *testing.T) {
	cases := map[string][]User{
		"empty":            {},
		"empty username":   {{Username: "", Password: "x"}},
		"blank username":   {{Username: "   ", Password: "x"}},
		"empty password":   {{Username: "a", Password: ""}},
		"crlf username":    {{Username: "a\rb", Password: "x"}},
		"crlf password":    {{Username: "a", Password: "x\ny"}},
		"duplicate name":   {{Username: "a", Password: "1"}, {Username: "a", Password: "2"}},
		"duplicate secret": {{Username: "a", Password: "same"}, {Username: "b", Password: "same"}},
	}
	for name, users := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewStore(users); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	s := testStore(t)
	if !s.Authenticate("alice", "alice-secret") {
		t.Fatal("valid credentials should verify")
	}
	if s.Authenticate("alice", "wrong") {
		t.Fatal("wrong password must not verify")
	}
	if s.Authenticate("carol", "alice-secret") {
		t.Fatal("unknown user must not verify")
	}
	if s.Authenticate("", "") {
		t.Fatal("empty credentials must not verify")
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
}

func TestSHA224HexKnownVector(t *testing.T) {
	// echo -n "password" | openssl dgst -sha224
	const want = "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
	if got := SHA224Hex("password"); got != want {
		t.Fatalf("SHA224Hex(password) = %s, want %s", got, want)
	}
	if len(SHA224Hex("")) != 56 {
		t.Fatal("hash length should be 56 hex chars")
	}
}

func TestVerifyTunnel(t *testing.T) {
	s := testStore(t)
	hash := SHA224Hex("bob-secret")

	if user, ok := s.VerifyTunnel(hash); !ok || user != "bob" {
		t.Fatalf("VerifyTunnel = (%q, %v), want (bob, true)", user, ok)
	}
	if user, ok := s.VerifyTunnel(strings.ToUpper(hash)); !ok || user != "bob" {
		t.Fatalf("uppercase hash should verify, got (%q, %v)", user, ok)
	}
	if _, ok := s.VerifyTunnel(SHA224Hex("not-a-user")); ok {
		t.Fatal("unknown hash must not verify")
	}

	for _, bad := range []string{"", "zzzz", strings.Repeat("a", 55), strings.Repeat("a", 57), SHA224Hex("x")[:30]} {
		if _, ok := s.VerifyTunnel(bad); ok {
			t.Fatalf("malformed hash %q must not verify", bad)
		}
	}
}

// BenchmarkStoreVerify 测量入站凭据校验热路径（SHA-256 摘要 + 常量时间比较）。
// 16 个用户的量级模拟小型自用部署；用户数不影响单次校验成本（map 查找 + 单次比较）。
func BenchmarkStoreVerify(b *testing.B) {
	users := make([]User, 0, 16)
	for i := 0; i < 16; i++ {
		users = append(users, User{
			Username: fmt.Sprintf("user-%02d", i),
			Password: fmt.Sprintf("secret-%02d", i),
		})
	}
	s, err := NewStore(users)
	if err != nil {
		b.Fatalf("NewStore: %v", err)
	}

	b.Run("hit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !s.Authenticate("user-07", "secret-07") {
				b.Fatal("valid credential must verify")
			}
		}
	})
	b.Run("miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if s.Authenticate("nobody", "secret-07") {
				b.Fatal("unknown user must not verify")
			}
		}
	})
}
