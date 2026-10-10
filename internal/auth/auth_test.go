package auth

import (
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

func TestVerify(t *testing.T) {
	s := testStore(t)
	if !s.Verify("alice", "alice-secret") {
		t.Fatal("valid credentials should verify")
	}
	if s.Verify("alice", "wrong") {
		t.Fatal("wrong password must not verify")
	}
	if s.Verify("carol", "alice-secret") {
		t.Fatal("unknown user must not verify")
	}
	if s.Verify("", "") {
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
