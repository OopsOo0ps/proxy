// Package testutil 提供测试辅助（自签证书等），仅测试代码使用。
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// NewTLSCertificate 生成 127.0.0.1 / localhost 的自签名服务端证书。
// 返回证书与 CA 证书的 PEM（自签名场景下为同一份）。
func NewTLSCertificate() (tls.Certificate, []byte, error) {
	cert, certPEM, _, err := newCert()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return cert, certPEM, nil
}

// newCert 生成密钥与自签证书，返回证书对象与 PEM 编码的证书、私钥。
func newCert() (tls.Certificate, []byte, []byte, error) {
	return newCertWithValidity(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

// newCertWithValidity 以指定有效期生成密钥与自签证书。
func newCertWithValidity(notBefore, notAfter time.Time) (tls.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "proxy-test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return cert, certPEM, keyPEM, nil
}

// WriteTLSCertFiles 生成自签证书并写入目录，返回 cert/key 文件路径。
func WriteTLSCertFiles(dir string) (certFile, keyFile string, err error) {
	_, certPEM, keyPEM, err := newCert()
	if err != nil {
		return "", "", err
	}
	return writeCertFiles(dir, certPEM, keyPEM)
}

// WriteTLSCertFilesWithValidity 生成指定有效期的自签证书并写入目录，
// 返回 cert/key 文件路径（用于过期证书等测试场景）。
func WriteTLSCertFilesWithValidity(dir string, notBefore, notAfter time.Time) (certFile, keyFile string, err error) {
	_, certPEM, keyPEM, err := newCertWithValidity(notBefore, notAfter)
	if err != nil {
		return "", "", err
	}
	return writeCertFiles(dir, certPEM, keyPEM)
}

// writeCertFiles 把证书与私钥 PEM 写入目录。
func writeCertFiles(dir string, certPEM, keyPEM []byte) (certFile, keyFile string, err error) {
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

// ClientTLSConfig 返回信任给定 CA PEM 的客户端 TLS 配置。
func ClientTLSConfig(caPEM []byte) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errBadCA
	}
	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}
