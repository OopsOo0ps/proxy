package clientapp_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OopsOo0ps/proxy/internal/clientapp"
	"github.com/OopsOo0ps/proxy/internal/config"
)

// TestExampleConfigsBuild 是 G4 示例可构造守护（设计文档 §6.2）：遍历
// configs/ 与 configs/local/ 中客户端侧的全部示例 YAML（命名约定：*server*
// 归 serverapp），config.Parse(data, KnownProtocols) + Build 必须全部成功。
// 防“示例配置与代码漂移”：协议 params 严格解码、信封校验、缺省值文档——
// 任何一侧漂移即失败。
//
// 注意：示例绑定固定演示端口；若本机正在运行 make demo，监听会因端口占用
// 失败——先 make demo-down 再跑测试。
func TestExampleConfigsBuild(t *testing.T) {
	t.Chdir(repoRoot(t)) // 规则文件等相对路径与运行时一致（make 从仓库根启动）
	paths := examplePaths(t, func(name string) bool {
		// 命名约定：*server* 归 serverapp；example-rules.yaml 是规则文档
		//（规则源 type: file 的内容），不是应用配置。
		return !strings.Contains(name, "server") && !strings.Contains(name, "rules")
	})
	if len(paths) == 0 {
		t.Fatal("test setup: no client example configs found")
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
			cfg, err := config.Parse(data, clientapp.KnownProtocols)
			if err != nil {
				t.Fatalf("config.Parse: %v", err)
			}
			rt, err := clientapp.Build(&cfg, clientapp.BuildOptions{})
			if err != nil {
				t.Fatalf("clientapp.Build: %v", err)
			}
			rt.Close()
		})
	}
}

// examplePaths 返回 configs/ 与 configs/local/ 中匹配命名约定的示例 YAML，
// 以仓库根为基准（规则文件等相对路径与运行时一致）。
func examplePaths(t *testing.T, keep func(name string) bool) []string {
	t.Helper()
	root := repoRoot(t)
	var paths []string
	for _, dir := range []string{"configs", filepath.Join("configs", "local")} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") || !keep(e.Name()) {
				continue
			}
			paths = append(paths, filepath.Join(root, dir, e.Name()))
		}
	}
	return paths
}

// repoRoot 返回模块根目录（go.mod 所在目录）；示例配置中的相对路径
// （规则文件、证书）都以它为基准（make 从仓库根启动进程）。
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
