package arch

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// wildcard 是「禁止一切 internal 包」的规则标记，例外名单见 allowAny。
const wildcard = "*"

// forbidden 是依赖守护矩阵：键为受管的 internal 包（模块内导入路径），
// 值为其（含传递依赖）禁止出现的 internal 包名。新包加入矩阵即受管。
// 矩阵与《核心模型抽象重构设计》2.2 节一致。
//
// 阶段 1 落位：入站三包（httpproxy / socks5 / dnsgw）只经 core 契约触达
// 出站能力；nodes / connpool 保持协议无关（不碰 trojan）且不反向依赖 config；
// core 是只依赖 routing 的纯契约层。
var forbidden = map[string][]string{
	"internal/httpproxy": {"nodes", "connpool", "trojan", "dialer", "outbound", "metrics", "config"},
	"internal/socks5":    {"nodes", "connpool", "trojan", "dialer", "outbound", "metrics", "config"},
	"internal/dnsgw":     {"nodes", "connpool", "trojan", "dialer", "outbound", "metrics", "config"},
	"internal/nodes":     {"metrics", "config", "trojan"},
	"internal/connpool":  {"metrics", "config", "trojan", "nodes"},
	"internal/core":      {wildcard},
}

// allowAny 是 wildcard 规则的例外名单：键为包，值为其仍允许依赖的 internal 包。
var allowAny = map[string][]string{
	"internal/core": {"routing"}, // routing.Action 是共享词汇（L0 纯叶子包）
}

// stage2Deferred 列出暂缓断言的 (包, 禁止项)：这些包当前仍直接消费
// *metrics.Metrics（字段注入的运行期指标），等遥测解耦（设计文档阶段 2，
// Observer 接口落地、L2/L3 删除 metrics import）完成后从本表移除并强制。
// 每个条目必须同时出现在 forbidden 中（见 TestDeferredRulesAreGoverned）。
var stage2Deferred = map[string][]string{
	"internal/httpproxy": {"metrics"},
	"internal/socks5":    {"metrics"},
	"internal/dnsgw":     {"metrics"},
	"internal/nodes":     {"metrics"},
	"internal/connpool":  {"metrics"},
}

// TestDependencyDirection 对矩阵中的每个包执行 go list -deps 并断言
// 完整传递依赖不含禁止项；命中即失败并打印违规 import 链。
func TestDependencyDirection(t *testing.T) {
	root := moduleRoot(t)
	module := modulePath(t, root)
	seedTestCacheInputs(t, root)

	for pkg, rules := range forbidden {
		t.Run(pkg, func(t *testing.T) {
			allow := allowAny[pkg]
			deferred := stage2Deferred[pkg]
			self := strings.TrimPrefix(pkg, "internal/")
			deps := internalDeps(t, root, module, pkg)

			var violations []string
			for _, dep := range deps {
				switch {
				case dep == self, slices.Contains(allow, dep), slices.Contains(deferred, dep):
					continue
				case slices.Contains(rules, dep) || slices.Contains(rules, wildcard):
					violations = append(violations, dep)
				}
			}
			if len(violations) == 0 {
				return
			}

			graph := importGraph(t, root, module, pkg)
			var b strings.Builder
			fmt.Fprintf(&b, "%s imports forbidden internal packages (forbidden: %v)", pkg, rules)
			for _, dep := range violations {
				from := module + "/" + pkg
				to := module + "/internal/" + dep
				fmt.Fprintf(&b, "\n  %s\n    import chain: %s", dep, strings.Join(importChain(graph, from, to), " -> "))
			}
			t.Fatal(b.String())
		})
	}
}

// TestDeferredRulesAreGoverned 保证暂缓名单没有游离于矩阵之外：暂缓条目
// 必须同时出现在 forbidden 里，否则它从未被治理——阶段 2 移除暂缓时会
// 静默漏掉本应生效的规则。
func TestDeferredRulesAreGoverned(t *testing.T) {
	for pkg, rules := range stage2Deferred {
		for _, dep := range rules {
			if !slices.Contains(forbidden[pkg], dep) {
				t.Errorf("%s defers %q, but forbidden[%s] does not list it", pkg, dep, pkg)
			}
		}
	}
}

// moduleRoot 返回模块根目录（go.mod 所在目录）。
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		t.Fatal("arch test must run inside the proxy module")
	}
	return filepath.Dir(gomod)
}

// modulePath 返回主模块的导入路径（如 github.com/OopsOo0ps/proxy）。
func modulePath(t *testing.T, root string) string {
	t.Helper()
	cmd := exec.Command("go", "list", "-m")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// internalDeps 返回 pkg 的完整传递依赖中模块内的 internal 包
// （internal/ 之后的相对路径，如 "nodes"）。
func internalDeps(t *testing.T, root, module, pkg string) []string {
	t.Helper()
	out := goList(t, root, module, pkg, "-deps")
	return cutInternal(module, string(out))
}

// importGraph 返回 pkg 依赖图中各包的直接导入（只保留模块内 internal 包，
// 键与值都是完整导入路径）。仅在断言失败后调用，用于还原违规链路。
func importGraph(t *testing.T, root, module, pkg string) map[string][]string {
	t.Helper()
	const template = "{{.ImportPath}} {{join .Imports \" \"}}"
	out := goList(t, root, module, pkg, "-deps", "-f", template)

	graph := make(map[string][]string)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var internalImports []string
		for _, imp := range fields[1:] {
			if strings.HasPrefix(imp, module+"/internal/") {
				internalImports = append(internalImports, imp)
			}
		}
		graph[fields[0]] = internalImports
	}
	return graph
}

// importChain 在 graph 中寻找 from 到 to 的导入路径（BFS），返回完整链
// （含两端）；不可达时返回仅含 to 的单元素链——go list -deps 给出的
// 传递闭包保证可达，此分支只为防御模板输出缺失。
func importChain(graph map[string][]string, from, to string) []string {
	prev := map[string]string{from: ""}
	queue := []string{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range graph[cur] {
			if _, seen := prev[next]; seen {
				continue
			}
			prev[next] = cur
			queue = append(queue, next)
		}
	}
	chain := []string{to}
	for cur := to; prev[cur] != ""; cur = prev[cur] {
		chain = append([]string{prev[cur]}, chain...)
	}
	return chain
}

// goList 在模块根目录执行 go list 并返回标准输出。
func goList(t *testing.T, root, module, pkg string, args ...string) []byte {
	t.Helper()
	argv := append(slices.Clone(args), module+"/"+pkg)
	cmd := exec.Command("go", append([]string{"list"}, argv...)...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list %s: %v\n%s", pkg, err, exitErr.Stderr)
		}
		t.Fatalf("go list %s: %v", pkg, err)
	}
	return out
}

// cutInternal 从 go list 输出中筛选模块内 internal 包，返回 internal/ 之后的
// 相对路径。
func cutInternal(module string, out string) []string {
	prefix := module + "/internal/"
	var deps []string
	for _, line := range strings.Fields(out) {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			deps = append(deps, rest)
		}
	}
	return deps
}

// seedTestCacheInputs 把受管包的源码文件登记为测试输入。
//
// go test 的结果缓存以测试进程打开的文件为键之一，而 go list 子进程的
// 读取不在键内——若不显式登记，其它包的源码变更不会让本测试重跑，
// 守护会被陈旧的 cached PASS 掩盖。读入受管包的全部 .go 文件后，
// 任何违规都必然伴随某个受管包源码变更，缓存随之失效。
func seedTestCacheInputs(t *testing.T, root string) {
	t.Helper()
	for pkg := range forbidden {
		dir := filepath.Join(root, pkg)
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || filepath.Ext(path) != ".go" {
				return nil
			}
			_, err = os.ReadFile(path)
			return err
		})
		if err != nil {
			t.Fatalf("seed test cache inputs from %s: %v", dir, err)
		}
	}
	// go.mod 决定模块路径与依赖集，同样登记为输入。
	if _, err := os.ReadFile(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("seed test cache input go.mod: %v", err)
	}
}
