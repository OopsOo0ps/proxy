package alipay

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// minRSABits 是 RSA2 密钥的最小模长（真实支付宝密钥为 2048 位；更短的密钥
// 按非法构造拒绝——fail-closed）。
const minRSABits = 2048

// parsePrivateKey 解析商户 RSA2 私钥 PEM：PKCS#8（-----BEGIN PRIVATE KEY-----）
// 优先，兼容 PKCS#1（-----BEGIN RSA PRIVATE KEY-----）。要求 RSA 且模长达标，
// 并做密钥自洽校验（Validate）。what 用于错误定位（"merchant key" 等）。
func parsePrivateKey(data []byte, what string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: %s: no PEM block found", ErrInvalidConfig, what)
	}
	var (
		key any
		err error
	)
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: %s: unsupported PEM block %q (want \"PRIVATE KEY\" or \"RSA PRIVATE KEY\")", ErrInvalidConfig, what, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidConfig, what, err)
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s: not an RSA private key", ErrInvalidConfig, what)
	}
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s: invalid key: %v", ErrInvalidConfig, what, err)
	}
	if priv.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("%w: %s: %d-bit RSA key, want >= %d bits", ErrInvalidConfig, what, priv.N.BitLen(), minRSABits)
	}
	priv.Precompute()
	return priv, nil
}

// parsePublicKey 解析支付宝公钥 PEM：PKIX（-----BEGIN PUBLIC KEY-----）优先，
// 兼容 PKCS#1（-----BEGIN RSA PUBLIC KEY-----）。要求 RSA 且模长达标。
func parsePublicKey(data []byte, what string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: %s: no PEM block found", ErrInvalidConfig, what)
	}
	var (
		key any
		err error
	)
	switch block.Type {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: %s: unsupported PEM block %q (want \"PUBLIC KEY\" or \"RSA PUBLIC KEY\")", ErrInvalidConfig, what, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidConfig, what, err)
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s: not an RSA public key", ErrInvalidConfig, what)
	}
	if pub.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("%w: %s: %d-bit RSA key, want >= %d bits", ErrInvalidConfig, what, pub.N.BitLen(), minRSABits)
	}
	return pub, nil
}
