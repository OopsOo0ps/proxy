// Package clientapp 组装 proxy-client（设计文档 §8 组装根）：解析配置 →
// 构建不可变运行时快照（含监听绑定）→ 原子切换 → 旧快照排空。
//
// 协议分派只有两个位置（全仓唯一，§7.4）：buildTransport 按出口协议
// protocol 分派（trojan → DecodeParams → trojan.NewTransport，协议校验在
// 构造器），buildInbound 按入站 type 分派（http / socks5 / dns）。switch
// 就是注册表：静态、可 grep、类型安全、fail-fast。
//
// 热加载语义（§8.2 重载语义表）：快照重建是默认路径——任何字段改动都会在
// 新快照中生效（"需重启字段"分类不存在）；规则表与日志级别走运行期热更；
// 上游栈（节点 + params + 池 + 超时）指纹未变时复用节点池 / 预热池实例。
// 关停期拒绝重载；重载失败时旧配置仍在原端口继续服务（同端口重绑冲突的
// 处置见 internal/lifecycle 的 switchTo）。
//
// 代码按职责拆分为同包多文件（assemble / dispatch / inbounds / outbound /
// dns / liveview / observers 等）；本文件保留包文档、构建依赖与 App 生命周期。
package clientapp

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/lifecycle"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/version"
)

// KnownProtocols 是本组装根能分派的协议全集（config 解析期校验依据）：
// 入站 http / socks5 / dns，出口 trojan。
var KnownProtocols = config.ProtocolSet{
	Inbounds: []string{config.TypeHTTP, config.TypeSOCKS5, config.TypeDNS},
	Outbound: []string{config.ProtocolTrojan},
}

// —— 构建依赖 ——

// BuildOptions 是包级 Build 的组装依赖（G4 示例配置守护测试与直接构造
// 场景使用；常驻服务经 New 构造）。
type BuildOptions struct {
	// Logger 记录构建期告警与请求日志；nil 时静默。
	Logger *slog.Logger
	// Metrics 是遥测与观察者出口；nil 时使用禁用集合的空指标。
	Metrics *metrics.Metrics
	// Limiter 是进程级并发闸；nil 时不限流。
	Limiter *connlimit.Limiter
	// Version 出现在 /stats。
	Version string
	// LogCtrl 是运行时可调日志控制器；nil 时 /log/level 端点不可用。
	LogCtrl *logging.Control
	// OnRulesChange 在规则表变化后被调用（丢弃转发路径空闲连接）；可 nil。
	OnRulesChange func()
}

// builder 承载一次组装的全部依赖；App 持有同一 builder 覆盖完整生命周期。
type builder struct {
	logger        *slog.Logger
	metrics       *metrics.Metrics
	limiter       *connlimit.Limiter
	dnsLimiter    *connlimit.Limiter
	version       string
	start         time.Time
	logCtrl       *logging.Control
	onRulesChange func()
	live          *atomic.Pointer[Runtime]
}

func newBuilder(opts BuildOptions, live *atomic.Pointer[Runtime]) builder {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	m := opts.Metrics
	if m == nil {
		m = metrics.New(nil)
	}
	return builder{
		logger:  logger,
		metrics: m,
		limiter: opts.Limiter,
		// DNS 用独立于进程全局闸的专用查询闸（上限与全局闸同源复用
		// limits.max-connections，不新增配置字段）：UDP 在途查询不是连接，
		// 不适合计入全局连接闸；且 DNS 洪水不应级联拒掉 HTTP/SOCKS5 的
		// 新连接。UDP 与 TCP 双栈共用这一份预算。
		dnsLimiter:    connlimit.New(opts.Limiter.Max()),
		version:       opts.Version,
		start:         time.Now(),
		logCtrl:       opts.LogCtrl,
		onRulesChange: opts.OnRulesChange,
		live:          live,
	}
}

// —— App：薄包装（生命周期核心见 internal/lifecycle）——

// App 是组装完成的 proxy-client 实例。
// 生命周期：New（构建快照并绑定监听）→ Serve（阻塞服务直到 ctx 取消）。
// 配置热加载见 Reload：先完整构建新快照，全部成功后原子切换并排空旧快照；
// 任何失败都保持旧配置在原端口继续服务。顺序与关停语义（代际切换、失败
// 回滚、fail-closed、按代际计数防 Add-after-Wait）全部由 internal/lifecycle
// 核心承载；本组装根只注入应用语义（组装、绑定、服务端点、运行期热更）。
type App struct {
	core *lifecycle.App[Runtime, *config.Config]
	b    builder
	live atomic.Pointer[Runtime] // 借给核心的组装根 live 指针（生效边界 = 新拨号）
}

// New 校验并组装应用：构建完整运行时快照并绑定全部监听（不变量 3：
// 任何失败关闭已打开的一切并返回错误）。logCtrl 是运行时可调日志控制器
// （可为 nil，此时 /log/level 端点不可用）。
func New(cfg *config.Config, logger *slog.Logger, logCtrl *logging.Control) (*App, error) {
	app := &App{}
	app.b = newBuilder(BuildOptions{
		Logger:        logger,
		Metrics:       metrics.New(enabledProtos(cfg)),
		Limiter:       connlimit.New(cfg.Limits.EffectiveMaxConnections()),
		Version:       version.Get().Version,
		LogCtrl:       logCtrl,
		OnRulesChange: app.dropForwardIdleConns,
	}, &app.live)
	core, _, err := lifecycle.New(lifecycleOptions(&app.b), cfg, &app.live)
	if err != nil {
		return nil, err
	}
	app.core = core
	return app, nil
}

// lifecycleOptions 把 clientapp 的应用语义注入生命周期核心：闭包一律经
// builder 指针运行期读取（测试会在 New 后替换 logger / logCtrl，钩子不得
// 捕获构造期值）。Name 前缀 "clientapp" 逐字复现既有错误与日志文案。
func lifecycleOptions(b *builder) lifecycle.Options[Runtime, *config.Config] {
	return lifecycle.Options[Runtime, *config.Config]{
		Name:     "clientapp",
		Assemble: b.assemble,
		Load:     loadConfigFile,
		Port: lifecycle.Port[Runtime]{
			// Clone 返回浅拷贝（c := *rt; return &c）：restore 回滚路径以
			// 克隆上线，旧代际（及其服务协程闭包）仍持原指针。
			Clone: func(rt *Runtime) *Runtime {
				c := *rt
				return &c
			},
			Services:       runtimeServices,
			Bind:           b.bindRuntime,
			CloseListeners: func(rt *Runtime) { rt.closeListeners() },
			CloseOwned:     func(cur, next *Runtime) { next.closeOwned(cur) },
			ReleaseReplaced: func(cur, next *Runtime) {
				cur.releaseReplaced(next)
			},
			StartResources: func(rt *Runtime, parent context.Context) {
				rt.startResources(parent)
			},
			CloseResources: func(rt *Runtime) { rt.closeResources() },
		},
		OnReloaded: func(next *config.Config) {
			b.limiter.SetMax(next.Limits.EffectiveMaxConnections())
			// DNS 专用查询闸与全局闸同源：热加载时同步调整上限。
			b.dnsLimiter.SetMax(next.Limits.EffectiveMaxConnections())
			if b.logCtrl != nil {
				b.logCtrl.SetLevel(next.Log.Level)
				b.logCtrl.SetFormat(next.Log.Format)
			}
			b.logger.Info("configuration reloaded",
				"inbounds", len(next.Inbounds),
				"nodes", len(nodesOf(next)),
				"max_connections", next.Limits.EffectiveMaxConnections(),
				"dns_gateway", dnsGatewayListen(next) != "",
			)
		},
		OnReloadResult: func(success bool) {
			if success {
				b.metrics.ConfigReload(metrics.ReloadSuccess)
				return
			}
			b.metrics.ConfigReload(metrics.ReloadError)
		},
		OnRollbackFailed: func(err error) {
			b.logger.Error("reload rollback failed; previous listeners could not be rebound", "error", err)
		},
	}
}

// runtimeServices 把运行时快照的服务端点暴露给生命周期核心（每次代际
// 上线时读取）：入站按声明顺序，错误前缀 "clientapp: inbound %s" 的 %s
// 即入站 type；运维端点错误前缀 "clientapp: admin endpoint"。
func runtimeServices(rt *Runtime) lifecycle.Services {
	svc := lifecycle.Services{Admin: lifecycle.Service{Serve: rt.Admin.Serve}}
	for i := range rt.Inbounds {
		is := &rt.Inbounds[i]
		svc.Inbounds = append(svc.Inbounds, lifecycle.Service{
			Kind:  is.Config.Type,
			Serve: is.Serve,
		})
	}
	return svc
}

// loadConfigFile 读取并解析客户端配置（lifecycle Load 钩子）；levelOverride
// 是启动参数 -log-level 的显式覆盖，非空时优先于文件值。
func loadConfigFile(path, levelOverride string) (*config.Config, error) {
	cfg, err := config.Load(path, KnownProtocols)
	if err != nil {
		return nil, err
	}
	if levelOverride != "" {
		cfg.Log.Level = levelOverride
	}
	return cfg, nil
}

// Build 依据配置构建完整运行时快照（含监听绑定）：除绑定外无副作用；
// 任何失败关闭已打开的一切并返回错误（不变量 3）。供 G4 示例配置守护
// 测试与直接构造场景使用；常驻服务请使用 New。
func Build(cfg *config.Config, opts BuildOptions) (*Runtime, error) {
	var live atomic.Pointer[Runtime]
	b := newBuilder(opts, &live)
	return lifecycle.Build(lifecycleOptions(&b), cfg, &live)
}

// enabledProtos 返回已启用的入站协议集合（metrics 按集合预初始化时间序列）。
func enabledProtos(cfg *config.Config) []string {
	seen := map[string]bool{}
	protos := make([]string, 0, len(cfg.Inbounds))
	for i := range cfg.Inbounds {
		var proto string
		switch cfg.Inbounds[i].Type {
		case config.TypeHTTP:
			proto = core.ProtoHTTP
		case config.TypeSOCKS5:
			proto = core.ProtoSOCKS5
		case config.TypeDNS:
			proto = core.ProtoDNS
		default:
			continue
		}
		if !seen[proto] {
			seen[proto] = true
			protos = append(protos, proto)
		}
	}
	return protos
}

// nodesOf 返回出口节点列表（未配置出站侧时为 nil）。
func nodesOf(cfg *config.Config) []config.Node {
	if cfg.Outbound == nil {
		return nil
	}
	return cfg.Outbound.Nodes
}

// dropForwardIdleConns 规则变化回调：丢弃当前快照转发路径的空闲上游连接。
func (a *App) dropForwardIdleConns() {
	if rt := a.live.Load(); rt != nil {
		rt.dropForwardIdleConns()
	}
}

// Serve 阻塞服务直到 ctx 取消或任一监听出错；返回前完成优雅关停
// （存量连接按排空期限收尾）。重载产出的新代际在切换时即上线，
// 不经过本函数的再次调度。
func (a *App) Serve(ctx context.Context) error { return a.core.Serve(ctx) }

// Reload 应用一份新配置（重载流水线，§8.2）：读文件与解析在上层完成；
// 这里先完整构建新运行时（规则源重检、指纹复用、协议传输与凭据重建），
// 全部成功后原子切换（先停旧监听再绑新监听，见 internal/lifecycle 的
// switchTo），旧快照排空。任何失败都返回错误并保持旧配置在原端口继续
// 服务——配置错误不会波及线上。
//
// 生效边界为“新拨号”：a.live 是全局原子快照，切换对新拨号立即生效，包括
// 被替换世代在途请求的后续拨号；请求级快照冻结不是本模型的语义。
func (a *App) Reload(next *config.Config) error { return a.core.Reload(next) }

// ReloadFile 读取、解析并应用配置文件（path 与启动时相同）。
// levelOverride 是启动参数 -log-level 的显式覆盖，非空时同样优先于文件值。
// 解析失败与构建失败一样保持旧配置继续服务，
// 并且每次尝试（无论失败在哪一步）都恰好计入一次 config_reloads_total。
func (a *App) ReloadFile(path, levelOverride string) error {
	return a.core.ReloadFile(path, levelOverride)
}

// Serving 报告应用是否正在服务（测试接缝：代际上线 / 关停的判定点）。
func (a *App) Serving() bool { return a.core.Serving() }

// —— 观测访问器 ——

// HTTPAddr 返回首个 HTTP 入站实际监听地址（未启用时为空）。
func (a *App) HTTPAddr() string { return a.inboundAddr(config.TypeHTTP) }

// SOCKS5Addr 返回首个 SOCKS5 入站实际监听地址（未启用时为空）。
func (a *App) SOCKS5Addr() string { return a.inboundAddr(config.TypeSOCKS5) }

// DNSAddr 返回首个 DNS 网关入站实际监听地址（未启用时为空）。
func (a *App) DNSAddr() string { return a.inboundAddr(config.TypeDNS) }

func (a *App) inboundAddr(t string) string {
	if rt := a.live.Load(); rt != nil {
		for i := range rt.Inbounds {
			if rt.Inbounds[i].Config.Type == t {
				return rt.Inbounds[i].Addr()
			}
		}
	}
	return ""
}

// MetricsAddr 返回运维端点实际监听地址（未启用时为空）。
func (a *App) MetricsAddr() string {
	if rt := a.live.Load(); rt != nil {
		return rt.Admin.Addr()
	}
	return ""
}
