// RSA2 演示密钥生成（测试辅助）：与 make dev-keys 同格式（商户私钥 PKCS#8、
// 公钥 PKIX，RSA 2048 位），供 G4 示例守护与控制面测试按需生成全新密钥——
// 密钥材料只落在 gitignored 的 var/ 或 t.TempDir()，永不进版本库。

package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// NewRSAKeyPEM 生成全新的 RSA 2048 密钥对，返回 PKCS#8（"PRIVATE KEY"）私钥
// PEM 与对应 PKIX（"PUBLIC KEY"）公钥 PEM——与 make dev-keys 产出的演示密钥
// 同格式（openssl genpkey / openssl pkey -pubout），可直接被 internal/alipay
// 的解析器与 config 的 merchant_key_file / alipay_public_key_file 消费。
func NewRSAKeyPEM() (privatePEM, publicPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	privatePEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	publicPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privatePEM, publicPEM, nil
}
