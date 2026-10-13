package arch

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// 守护测试（设计文档 §6.2）：规则全部从 layering.go 的数据推导，测试本身
// 不持有任何例外清单。四条守护：
//
//  1. TestDependencyDirection —— 依赖方向 + 完备性 + 外部依赖属主；
//  2. TestProtocolLeak       —— 协议词汇泄漏（含测试文件的 import）；
//  3. TestGoModAllowlist     —— go.mod 直接依赖按属主收口；
//  4. TestExportedInterfaceInventory —— 导出接口面清点（新增必须显式改清单）。
//
// 完备性即强制：测试从 go list ./... 出发枚举真实包集合，而不是遍历手工
// 矩阵——把新包加进仓库这个动作本身就会让测试失败。

// TestDependencyDirection 对 go list 枚举出的每个真实包断言：
//   - 已在 Layers 登记（完备性即强制，未登记 = FAIL 并提示归类）；
//   - 每条非测试 import：标准库放行；模块内 import 的层号必须严格更小，
//     或命中 SameLayerEdges 声明的同层边；外部依赖必须属主（ExternalDeps）。
func TestDependencyDirection(t *testing.T) {
	root := moduleRoot(t)
	seedTestCacheInputs(t, root)
	std := stdlibPackages(t)

	for _, p := range listPackages(t, root) {
		p := p
		t.Run(p.key, func(t *testing.T) {
			layer, ok := Layers[p.key]
			if !ok {
				t.Fatalf("包 %q 未在 Layers 登记：新包必须先归类（层号 + 归入理由，见 internal/arch/layering.go）", p.key)
			}
			for _, imp := range p.imports {
				switch {
				case std[imp]:
					// 标准库不受分层约束。
				case strings.HasPrefix(imp, p.module+"/"):
					depKey, ok := packageKey(p.module, imp)
					if !ok {
						t.Errorf("%s(L%d) import 未登记的模块内包 %s", p.key, layer, imp)
						continue
					}
					depLayer, ok := Layers[depKey]
					if !ok {
						t.Errorf("%s import 模块内包 %s：该包未在 Layers 登记，先归类再依赖", p.key, imp)
						continue
					}
					if depLayer < layer {
						continue
					}
					if depLayer == layer && sameLayerEdge(p.key, depKey) {
						continue
					}
					t.Errorf("%s(L%d) 不得 import %s(L%d)：层号必须严格更小，或命中 SameLayerEdges 声明的同层边",
						p.key, layer, depKey, depLayer)
				default:
					if !ownedBy(imp, p.key) {
						t.Errorf("%s import 外部依赖 %s：非属主包（ExternalDeps 只允许属主触达）", p.key, imp)
					}
				}
			}
		})
	}
}

// TestProtocolLeak 断言协议包只被其 ProtocolPkgs allowlist 内的包触达：
// 对普通 import 与测试 import（包内测试 + 外部测试）双查；外部测试包
// （foo_test）按其宿主包归属判定。
func TestProtocolLeak(t *testing.T) {
	for _, p := range listPackages(t, moduleRoot(t)) {
		for _, imp := range p.allImports() {
			key, ok := packageKey(p.module, imp)
			if !ok {
				continue
			}
			allow, ok := ProtocolPkgs[key]
			if !ok {
				continue // 非协议包不在此守护范围内
			}
			if !slices.Contains(allow, p.key) {
				t.Errorf("%s import 协议包 %s：协议词汇只允许 %v 触达（ProtocolPkgs，见 layering.go）",
					p.key, key, allow)
			}
		}
	}
}

// TestGoModAllowlist 断言 go.mod 的直接 require ⊆ ExternalDeps 键集：
// 第三方依赖必须先登记属主（防依赖蔓延，设计文档 §6.3）。
func TestGoModAllowlist(t *testing.T) {
	root := moduleRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, mod := range directRequires(string(data)) {
		if _, ok := ExternalDeps[mod]; !ok {
			t.Errorf("go.mod 直接依赖 %s 未在 ExternalDeps 登记：新依赖必须先登记属主包（layering.go）", mod)
		}
	}
}

// exportedInterfaces 是当前 module 全部导出接口的清点（非测试文件，格式
// "包名.接口名"）。设计文档 §11.2 的量化承诺是「全仓导出接口 ≤ 15 个」，
// 现状为 20 个（§4.4 契约表 + 各组件 Observer/LivePolicy 的消费方锚点 +
// 入站一致性套件的 Inbound 夹具锚点，逐个有存在理由）。本测试钉住精确
// 集合：新增或删除接口都必须显式修改本清单——接口面在收敛回 ≤15 之前
// 不允许静默生长。
var exportedInterfaces = []string{
	"connpool.Observer",
	"core.Authenticator",
	"core.TargetDialer",
	"core.Telemetry",
	"dialer.Router",
	"dnsgw.DNSObserver",
	"dnsgw.LivePolicy",
	"dnsgw.RouteDecider",
	"httpproxy.LivePolicy",
	"nodes.Observer",
	"outbound.Prepared",
	"outbound.Prober",
	"outbound.Prewarmer",
	"outbound.Transport",
	"ruleset.Observer",
	"session.ConnHandler",
	"socks5.LivePolicy",
	"testutil.Inbound",
	"trojan.LivePolicy",
	"trojan.Verifier",
}

// TestExportedInterfaceInventory 用 go/parser 清点 module 内非测试文件的
// 导出 interface 类型，与上面手工维护的清点对照：多出（未评审的新接口）
// 或缺失（已删除但清单未更新）都判失败。
func TestExportedInterfaceInventory(t *testing.T) {
	got := scanExportedInterfaces(t, moduleRoot(t))

	want := slices.Sorted(slices.Values(exportedInterfaces))
	var added, removed []string
	for _, name := range got {
		if !slices.Contains(want, name) {
			added = append(added, name)
		}
	}
	for _, name := range want {
		if !slices.Contains(got, name) {
			removed = append(removed, name)
		}
	}
	if len(added) > 0 || len(removed) > 0 {
		t.Fatalf("导出接口清点漂移（当前 %d 个，清单 %d 个）：\n  新增: %v\n  缺失: %v\n新增接口必须在 layering.go 的清单登记存在理由；删除接口请同步更新清单",
			len(got), len(want), added, removed)
	}
}

// —— 测试辅助 ——

// pkgSnapshot 是 go list 枚举出的一个包：导入路径、分层键与 import 集合。
type pkgSnapshot struct {
	module       string // 主模块导入路径
	path         string // 完整导入路径
	key          string // Layers / ProtocolPkgs 的键
	imports      []string
	testImports  []string // 包内测试（package foo）
	xtestImports []string // 外部测试（package foo_test）
}

func (p pkgSnapshot) allImports() []string {
	var out []string
	out = append(out, p.imports...)
	out = append(out, p.testImports...)
	out = append(out, p.xtestImports...)
	return out
}

// listPackages 执行一次 go list ./... 枚举模块内的真实包集合。
func listPackages(t *testing.T, root string) []pkgSnapshot {
	t.Helper()
	const template = "{{.ImportPath}}|{{join .Imports \" \"}}|{{join .TestImports \" \"}}|{{join .XTestImports \" \"}}"
	out := goList(t, root, "./...", template)

	module := modulePath(t, root)
	var pkgs []pkgSnapshot
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Split(line, "|")
		if len(parts) != 4 {
			t.Fatalf("unexpected go list output: %q", line)
		}
		key, ok := packageKey(module, parts[0])
		if !ok {
			t.Fatalf("模块根出现包 %s：它不在 internal/ cmd/ test/ 之下，无法纳入分层管理", parts[0])
		}
		pkgs = append(pkgs, pkgSnapshot{
			module:       module,
			path:         parts[0],
			key:          key,
			imports:      fields(parts[1]),
			testImports:  fields(parts[2]),
			xtestImports: fields(parts[3]),
		})
	}
	return pkgs
}

// stdlibPackages 返回标准库导入路径集合（go list std，权威判定）。
func stdlibPackages(t *testing.T) map[string]bool {
	t.Helper()
	out := goList(t, moduleRoot(t), "std", "{{.ImportPath}}")
	std := make(map[string]bool)
	for _, line := range strings.Fields(string(out)) {
		std[line] = true
	}
	return std
}

// packageKey 把模块内导入路径映射为 Layers 的键：internal/ 下的包取
// internal/ 之后的相对路径，cmd/ 与 test/ 保留目录前缀。
func packageKey(module, path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, module+"/")
	if !ok {
		return "", false
	}
	if dir, ok := strings.CutPrefix(rest, "internal/"); ok {
		return dir, true
	}
	return rest, true
}

// sameLayerEdge 报告 from → to 是否为 SameLayerEdges 声明的受控同层边。
func sameLayerEdge(from, to string) bool {
	return slices.Contains(SameLayerEdges[from], to)
}

// ownedBy 报告外部依赖 imp 是否属于 pkg：imp 必须命中某个 ExternalDeps
// 键（module 路径或其子包），且 pkg 在该键的属主列表内。
func ownedBy(imp, pkg string) bool {
	for mod, owners := range ExternalDeps {
		if imp != mod && !strings.HasPrefix(imp, mod+"/") {
			continue
		}
		return slices.Contains(owners, pkg)
	}
	return false
}

// directRequires 从 go.mod 文本解析直接依赖（require 块内的非 indirect 条目，
// 兼容单行 require 形式）。
func directRequires(data string) []string {
	var out []string
	inBlock := false
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "//"):
			continue
		case strings.HasPrefix(line, "require ("):
			inBlock = true
		case inBlock && line == ")":
			inBlock = false
		case strings.HasPrefix(line, "require"):
			if mod, ok := requireModule(strings.TrimPrefix(line, "require")); ok {
				out = append(out, mod)
			}
		case inBlock:
			if mod, ok := requireModule(line); ok {
				out = append(out, mod)
			}
		}
	}
	return out
}

// requireModule 解析一行 require 条目「module path v1.2.3 [// indirect]」。
func requireModule(line string) (string, bool) {
	if strings.Contains(line, "// indirect") {
		return "", false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", false
	}
	return fields[0], true
}

// scanExportedInterfaces 用 go/parser 扫描 module 内非测试 Go 文件，
// 返回全部导出 interface 类型（"包名.类型名"，升序）。
func scanExportedInterfaces(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".bin", ".gocache", ".gopath", "bin", "var", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if _, ok := ts.Type.(*ast.InterfaceType); ok && ts.Name.IsExported() {
					out = append(out, file.Name.Name+"."+ts.Name.Name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan exported interfaces: %v", err)
	}
	return slices.Sorted(slices.Values(out))
}

// moduleRoot 返回模块根目录（go.mod 所在目录）。
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := goOutput(t, "env", "GOMOD")
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
	out, err := goOutputIn(t, root, "list", "-m")
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// goList 在 root 目录执行 go list，以 template 格式化输出。
func goList(t *testing.T, root, pattern, template string) []byte {
	t.Helper()
	out, err := goOutputIn(t, root, "list", "-f", template, pattern)
	if err != nil {
		t.Fatalf("go list %s: %v", pattern, err)
	}
	return out
}

// goOutputIn / goOutput 执行 go 子命令并返回标准输出。
func goOutputIn(t *testing.T, dir string, args ...string) ([]byte, error) {
	t.Helper()
	return goOutput(t, append([]string{"-C", dir}, args...)...)
}

func goOutput(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	return exec.Command("go", args...).Output()
}

// seedTestCacheInputs 把模块内全部 Go 源文件与 go.mod / go.sum 登记为测试
// 输入。go test 的结果缓存以测试进程打开的文件为键之一，而 go list 子进程
// 的读取不在键内——若不显式登记，其它包的源码变更不会让本测试重跑，守护
// 会被陈旧的 cached PASS 掩盖。读入全部源文件后，任何违规都必然伴随某个
// 源码变更，缓存随之失效。
func seedTestCacheInputs(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".bin", ".gocache", ".gopath", "bin", "var", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(path, ".go"), strings.HasSuffix(path, "go.mod"), strings.HasSuffix(path, "go.sum"):
			_, err = os.ReadFile(path)
		}
		return err
	})
	if err != nil {
		t.Fatalf("seed test cache inputs: %v", err)
	}
}

// fields 把空白分隔的模板字段切为切片（空串返回 nil）。
func fields(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Fields(s)
}
