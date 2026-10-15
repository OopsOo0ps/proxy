package alipay

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

// TestParsePrivateKeyAcceptedForms 钉死商户私钥的两种真实 PEM 形态：
// PKCS#8（-----BEGIN PRIVATE KEY-----，make dev-keys 的产出）与
// PKCS#1（-----BEGIN RSA PRIVATE KEY-----，老工具链常见）。
func TestParsePrivateKeyAcceptedForms(t *testing.T) {
	for name, pemStr := range map[string]string{
		"pkcs8": testMerchantKeyPEM,
		"pkcs1": string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(mustMerchantKey(t)),
		})),
	} {
		t.Run(name, func(t *testing.T) {
			key, err := parsePrivateKey([]byte(pemStr), "merchant key")
			if err != nil {
				t.Fatalf("parsePrivateKey(%s): %v", name, err)
			}
			if key.N.BitLen() != 2048 {
				t.Fatalf("解析出 %d 位密钥，want 2048", key.N.BitLen())
			}
		})
	}
}

// TestParsePrivateKeyRejections 钉死私钥负例：非 PEM、块类型不符、坏 DER、
// 非 RSA（EC）、模长不足——全部构造期拒绝（fail-closed）。
func TestParsePrivateKeyRejections(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal ecdsa key: %v", err)
	}
	shortRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate short rsa key: %v", err)
	}
	cases := map[string][]byte{
		"not-pem":          []byte("this is not a PEM block"),
		"wrong-block-type": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
		"corrupt-der":      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not der")}),
		"not-rsa":          pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}),
		"too-short":        pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(shortRSA)}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePrivateKey(data, "merchant key"); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("必须以 ErrInvalidConfig 拒绝，got %v", err)
			}
		})
	}
}

// TestParsePublicKeyAcceptedForms 钉死支付宝公钥的两种真实 PEM 形态：
// PKIX（-----BEGIN PUBLIC KEY-----，开放平台控制台产出）与 PKCS#1。
func TestParsePublicKeyAcceptedForms(t *testing.T) {
	for name, pemStr := range map[string]string{
		"pkix":  testGatewayPubPEM,
		"pkcs1": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(mustGatewayPub(t))})),
	} {
		t.Run(name, func(t *testing.T) {
			key, err := parsePublicKey([]byte(pemStr), "alipay key")
			if err != nil {
				t.Fatalf("parsePublicKey(%s): %v", name, err)
			}
			if key.N.BitLen() != 2048 {
				t.Fatalf("解析出 %d 位密钥，want 2048", key.N.BitLen())
			}
		})
	}
}

// TestParsePublicKeyRejections 钉死公钥负例：非 PEM、块类型不符、坏 DER、
// 非 RSA（ed25519）、模长不足。
func TestParsePublicKeyRejections(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	edDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("marshal ed25519 key: %v", err)
	}
	shortRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate short rsa key: %v", err)
	}
	cases := map[string][]byte{
		"not-pem":          []byte("still not a PEM block"),
		"wrong-block-type": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
		"corrupt-der":      pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not der")}),
		"not-rsa":          pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDER}),
		"too-short":        pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&shortRSA.PublicKey)}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePublicKey(data, "alipay key"); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("必须以 ErrInvalidConfig 拒绝，got %v", err)
			}
		})
	}
}
