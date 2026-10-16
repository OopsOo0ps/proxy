package serverapp_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/serverapp"
	"github.com/OopsOo0ps/proxy/internal/testutil"
)

// TestExampleConfigsBuild 是 G4 示例可构造守护（设计文档 §6.2）：遍历
// configs/ 与 configs/local/ 中服务端侧的全部示例 YAML（命名约定：*server*
// 归 serverapp），config.Parse(data, KnownProtocols) + Build 必须全部成功。
// 防“示例配置与代码漂移”：协议 params 严格解码、信封校验、缺省值文档——
// 任何一侧漂移即失败。
//
// 示例引用 var/dev-cert.pem（make dev-cert 生成，var/ 已忽略）与
// var/alipay-merchant-key.pem、var/alipay-gateway-pub.pem（make dev-keys 生成）：
// 缺失时由本测试生成，保证全新检出直接 go test 也能守护。示例绑定固定演示端口；
// 若本机正在运行 make demo，监听会因端口占用失败——先 make demo-down。
func TestExampleConfigsBuild(t *testing.T) {
	t.Chdir(repoRoot(t))
	ensureDevCerts(t)
	ensureDevPayKeys(t)

	paths := examplePaths(t)
	if len(paths) == 0 {
		t.Fatal("test setup: no server example configs found")
	}
	for _, path := range paths {
		path := path
		rel, err := filepath.Rel(repoRoot(t), path)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(filepath.ToSlash(rel), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			cfg, err := config.Parse(data, serverapp.KnownProtocols)
			if err != nil {
				t.Fatalf("config.Parse: %v", err)
			}
			rt, err := serverapp.Build(&cfg, serverapp.BuildOptions{})
			if err != nil {
				t.Fatalf("serverapp.Build: %v", err)
			}
			rt.Close()
		})
	}
}

// examplePaths 返回 configs/ 与 configs/local/ 中文件名含 server 的示例 YAML。
func examplePaths(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	var paths []string
	for _, dir := range []string{"configs", filepath.Join("configs", "local")} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") || !strings.Contains(e.Name(), "server") {
				continue
			}
			paths = append(paths, filepath.Join(root, dir, e.Name()))
		}
	}
	return paths
}

// ensureDevCerts 保证 var/dev-cert.pem 与 var/dev-key.pem 存在（示例配置
// 引用它们；缺失时用测试工具生成，与 make dev-cert 同路径同用途）。
func ensureDevCerts(t *testing.T) {
	t.Helper()
	cert, key := filepath.Join("var", "dev-cert.pem"), filepath.Join("var", "dev-key.pem")
	if _, err := os.Stat(cert); err == nil {
		if _, err := os.Stat(key); err == nil {
			return
		}
	}
	if err := os.MkdirAll("var", 0o755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("var", "g4-certs-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	gotCert, gotKey, err := testutil.WriteTLSCertFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	for from, to := range map[string]string{gotCert: cert, gotKey: key} {
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// ensureDevPayKeys 保证 var/alipay-merchant-key.pem 与 var/alipay-gateway-pub.pem
// 存在（示例 payment 段引用它们）。缺失时生成一对全新的 RSA2 2048 演示密钥，
// 格式与 make dev-keys 逐字一致：商户私钥 PKCS#8（0600 落盘——仓库安全底线：
// 私钥材料只落 gitignored 的 var/，永不进版本库）、支付宝公钥 PKIX。
func ensureDevPayKeys(t *testing.T) {
	t.Helper()
	merchantKey := filepath.Join("var", "alipay-merchant-key.pem")
	gatewayPub := filepath.Join("var", "alipay-gateway-pub.pem")
	if _, err := os.Stat(merchantKey); err == nil {
		if _, err := os.Stat(gatewayPub); err == nil {
			return
		}
	}
	if err := os.MkdirAll("var", 0o755); err != nil {
		t.Fatal(err)
	}
	merchantPriv, _, err := testutil.NewRSAKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, gatewayPubPEM, err := testutil.NewRSAKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(merchantKey, merchantPriv, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gatewayPub, gatewayPubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

// repoRoot 返回模块根目录（go.mod 所在目录）；示例配置中的相对路径
// （证书、规则文件）都以它为基准（make 从仓库根启动进程）。
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
