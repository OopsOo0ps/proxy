// Package lifecycle 承载组装根（clientapp / serverapp）共有的生命周期与
// 热加载流水线（设计文档 §8.2）：构建快照 → 绑定监听 → 原子切换 → 旧快照
// 排空。核心不感知具体运行时与配置类型（泛型 RT / C），全部应用语义经
// Port（运行时操作面）与 Options（组装 / 配置加载 / 回调）两组钩子注入；
// 本包只保留与协议无关的顺序与关停语义：
//
//   - startGeneration：先启动后台资源（绑定应用级 ctx，寿命 = 实例寿命，
//     不随代际结束而停止），再按「入站数 + 运维端点 + 控制面（可选）」先
//     计数后 spawn 服务协程（done 关闭不早于计数，避免 Add-after-Wait 竞态）；
//     代际 ctx 取消触发各端点既有 drain/force 语义；
//   - switchTo 三阶段：停旧（取消旧代际 ctx → 关旧监听）→ 绑新（失败
//     回滚：关新监听 → CloseOwned → restore）→ 提交（live.Store → 上线
//     新代际 → 最后释放被替换资源——顺序颠倒会误关新代际共享的池）；
//   - restore：按旧运行时自身已解析地址端口稳定重绑（:0 入站回滚后保持
//     原端口，与 switchTo 成功路径同语义）并经 Clone 浅拷贝上线恢复代际
//     ——必须走 Clone，不得 Store 原 rt（旧代际仍持有该指针）；restore
//     也失败则 fail-closed（记录首个致命错误并触发应用级关停）；
//   - Reload：关停期拒绝重载；构建 / 切换失败保持旧配置继续服务；每次
//     尝试（无论失败在哪一步）恰好记账一次（OnReloadResult）。
//
// 生效边界由组装根持有的 live 指针决定：New / Build 必须接收组装根的
// live *atomic.Pointer[RT]（组装根 builder 与 core 共用同一指针），核心
// 不自持局部 live——这是「切换对新拨号 / 新握手立即生效」的关键。
//
// 分层 L1：只依赖标准库；不 import 任何模块内包。
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// Service 是单个可服务端点的运行期句柄（函数字段形态：共享包不引入接口，
// 见 internal/arch 的导出接口清点守护）。
type Service struct {
	// Kind 是观测名：入站为入站 type（错误前缀 "%s: inbound %s"）。
	Kind string
	// Serve 阻塞服务直到 ctx 取消：停止接受新连接，存量连接按排空语义收尾。
	Serve func(ctx context.Context) error
}

// Services 是一次快照暴露给生命周期核心的全部服务端点（入站 + 运维端点 +
// 控制面）。
type Services struct {
	// Inbounds 是全部入站端点（按声明顺序 spawn）。
	Inbounds []Service
	// Admin 是运维端点（错误前缀 "%s: admin endpoint"）。
	Admin Service
	// Control 是控制面端点（错误前缀 "%s: control endpoint"）；零值 = 无
	// 控制面服务（不 spawn 协程、不计入代际协程数，语义与 Admin 一致）。
	Control Service
}

// Port 是运行时快照的全部可操作面（组装根注入）：生命周期核心只经这些
// 钩子触碰 RT，自身不感知 clientapp / serverapp 的任何类型。组装根不适用
// 的钩子（如无后台资源的快照）以显式 no-op 闭包提供，不用 nil。
type Port[RT any] struct {
	// Clone 返回浅拷贝（c := *r; return &c）。restore 用它上线恢复代际：
	// 旧代际仍持原指针，不得 Store 原 rt。
	Clone func(*RT) *RT
	// Services 返回该快照暴露的全部服务端点（每次上线时读取，运行期生效）。
	Services func(*RT) Services
	// Bind 绑定快照的全部监听（承载 bindRuntime）；previous 非 nil 时按其
	// 已解析地址做端口稳定重绑（端口 0 的配置重载后保持原端口）。
	Bind func(rt, previous *RT) error
	// CloseListeners 关闭全部监听（幂等）。
	CloseListeners func(*RT)
	// CloseOwned 关闭 next 新建（非复用 cur）的资源：构建 / 绑定失败的
	// 清理路径（不变量 3：失败路径关闭已打开的一切）。
	CloseOwned func(cur, next *RT)
	// ReleaseReplaced 释放被 next 替换的旧资源（提交路径的最后一步：
	// 新代际已上线后再释放，避免误关新代际复用的池）。
	ReleaseReplaced func(cur, next *RT)
	// StartResources 启动快照的后台资源，parent 是应用级 ctx（寿命 =
	// 实例寿命，不随代际结束而停止）；无后台资源的组装根用显式 no-op。
	StartResources func(rt *RT, parent context.Context)
	// CloseResources 关闭快照的后台资源（应用级关停路径）；无则显式 no-op。
	CloseResources func(*RT)
}

// Options 是组装根注入的应用语义（组装 / 配置加载 / 运行期热更与记账回调）。
type Options[RT any, C any] struct {
	// Name 出现在错误与日志前缀（"clientapp" / "serverapp"）。
	Name string
	// Assemble 依据配置构建完整运行时（不绑定监听）；reuse 非 nil 时复用
	// 未变更资源。构建失败不得产生外部副作用（新建资源自行关闭）。
	Assemble func(cfg C, reuse *RT) (*RT, error)
	// Load 读取并解析配置文件（ReloadFile 用）；levelOverride 非空时优先
	// 于文件值。
	Load func(path, levelOverride string) (C, error)
	// Port 是运行时操作面。
	Port Port[RT]
	// OnReloaded 在切换成功后被调用（限流上限 / 日志级别 / 成功日志等
	// 运行期热更副作用）；nil 时跳过。
	OnReloaded func(C)
	// OnReloadResult 记账每次重载尝试（成功与失败各恰一次）；nil 时跳过。
	OnReloadResult func(success bool)
	// OnRollbackFailed 在回滚也失败（fail-closed）后被调用（组装根在此
	// 记录错误日志）；nil 时跳过。
	OnRollbackFailed func(error)
}

// generation 是一次快照上线后的服务代际：代际 ctx 取消触发该代际全部入站
// 与运维端点的既有 drain/force 语义。每个代际持有独立的服务协程计数与
// done 信号：Serve 等待“当前代际”退出，重载以新代际整体替换——跨代际
// 共享一个 WaitGroup 会在新旧交替的间隙归零，使 Wait 提前返回
// （Add-after-Wait 竞态），这是按代际计数的根本原因。
type generation[RT any] struct {
	rt     *RT
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	done   chan struct{} // 全部服务协程退出后关闭
}

// App 是生命周期核心：Serve（阻塞服务直到 ctx 取消）、Reload / ReloadFile
// （热加载流水线）。live 是组装根持有的原子快照指针（借入，不拥有）。
type App[RT any, C any] struct {
	live *atomic.Pointer[RT] // 组装根与 builder 共用（生效边界 = 新拨号/新握手）
	gen  atomic.Pointer[generation[RT]]

	reloadMu  sync.Mutex
	closing   atomic.Bool
	serving   atomic.Bool
	serveCtx  context.Context // Serve 启动后写入；重载以此为父 ctx
	appCancel context.CancelFunc

	errMu    sync.Mutex
	firstErr error

	opts Options[RT, C]
}

// validate 校验必填钩子非 nil（防漏配）：核心在错误与关停路径依赖它们，
// 缺失会被静默吞掉，宁可在构造期直接失败。回调钩子（OnReloaded /
// OnReloadResult / OnRollbackFailed）可 nil，nil 时跳过对应副作用。
func validate[RT any, C any](opts Options[RT, C]) error {
	switch {
	case opts.Name == "":
		return errors.New("lifecycle: options.name must not be empty")
	case opts.Assemble == nil:
		return errors.New("lifecycle: options.assemble must not be nil")
	case opts.Load == nil:
		return errors.New("lifecycle: options.load must not be nil")
	case opts.Port.Clone == nil:
		return errors.New("lifecycle: options.port.clone must not be nil")
	case opts.Port.Services == nil:
		return errors.New("lifecycle: options.port.services must not be nil")
	case opts.Port.Bind == nil:
		return errors.New("lifecycle: options.port.bind must not be nil")
	case opts.Port.CloseListeners == nil:
		return errors.New("lifecycle: options.port.close-listeners must not be nil")
	case opts.Port.CloseOwned == nil:
		return errors.New("lifecycle: options.port.close-owned must not be nil")
	case opts.Port.ReleaseReplaced == nil:
		return errors.New("lifecycle: options.port.release-replaced must not be nil")
	case opts.Port.StartResources == nil:
		return errors.New("lifecycle: options.port.start-resources must not be nil")
	case opts.Port.CloseResources == nil:
		return errors.New("lifecycle: options.port.close-resources must not be nil")
	}
	return nil
}

// assembleAndBind 构建运行时并绑定全部监听（不变量 3：绑定失败关闭已
// 打开的一切并返回错误）。
func assembleAndBind[RT any, C any](opts Options[RT, C], cfg C) (*RT, error) {
	rt, err := opts.Assemble(cfg, nil)
	if err != nil {
		return nil, err
	}
	if err := opts.Port.Bind(rt, nil); err != nil {
		// CloseOwned(cur, next) 关闭 next 中非复用 cur 的资源（不变量 3）。
		opts.Port.CloseOwned(nil, rt)
		return nil, err
	}
	return rt, nil
}

// New 校验钩子并组装应用：构建完整运行时快照并绑定全部监听，存入组装根
// 的 live 指针（核心借用同一指针，不自持局部 live）。返回核心实例与首个
// 运行时快照。
func New[RT any, C any](opts Options[RT, C], cfg C, live *atomic.Pointer[RT]) (*App[RT, C], *RT, error) {
	if err := validate(opts); err != nil {
		return nil, nil, err
	}
	rt, err := assembleAndBind(opts, cfg)
	if err != nil {
		return nil, nil, err
	}
	live.Store(rt)
	return &App[RT, C]{live: live, opts: opts}, rt, nil
}

// Build 依据配置构建完整运行时快照（含监听绑定），不经 App 生命周期：
// 供示例配置守护测试与直接构造场景使用；常驻服务请使用 New。
func Build[RT any, C any](opts Options[RT, C], cfg C, live *atomic.Pointer[RT]) (*RT, error) {
	if err := validate(opts); err != nil {
		return nil, err
	}
	rt, err := assembleAndBind(opts, cfg)
	if err != nil {
		return nil, err
	}
	live.Store(rt)
	return rt, nil
}

// Serve 阻塞服务直到 ctx 取消或任一监听出错；返回前完成优雅关停
// （存量连接按排空期限收尾）。重载产出的新代际在切换时即上线，
// 不经过本函数的再次调度。
func (a *App[RT, C]) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	a.reloadMu.Lock()
	a.serveCtx = ctx
	a.appCancel = cancel
	gen := a.gen.Load()
	if gen == nil {
		gen = a.startGeneration(a.live.Load())
	}
	a.serving.Store(true)
	a.reloadMu.Unlock()
	defer func() {
		a.reloadMu.Lock()
		a.serving.Store(false)
		a.closing.Store(true)
		a.reloadMu.Unlock()
	}()

	// 应用级关停：取消当前代际（触发 drain/force）并立即释放池内空闲连接
	//（它们没有在途数据，提前关闭既让服务端尽快回收，也避免排空期的新请求
	// 再领取）。无后台资源的组装根（serverapp）注入的 CloseResources 是
	// 显式 no-op，语义等价于其原始实现。
	go func() {
		<-ctx.Done()
		if g := a.gen.Load(); g != nil {
			g.cancel()
		}
		if rt := a.live.Load(); rt != nil {
			a.opts.Port.CloseResources(rt)
		}
	}()

	for {
		<-gen.done
		// 当前代际退出：应用级关停、被重载替换、或服务协程全部意外结束。
		if ctx.Err() != nil {
			// 等待当前代际排空完成（重载可能刚替换过代际）。
			a.reloadMu.Lock()
			latest := a.gen.Load()
			a.reloadMu.Unlock()
			if latest != nil && latest != gen {
				<-latest.done
			}
			return a.firstError()
		}
		a.reloadMu.Lock()
		latest := a.gen.Load()
		a.reloadMu.Unlock()
		if latest == gen {
			// 未被替换且无关停信号：全部服务协程结束（如监听被外部关闭）。
			return a.firstError()
		}
		gen = latest
	}
}

// startGeneration 让快照上线：启动后台资源并 spawn 全部服务协程。
// 必须在 reloadMu 持有时调用。
func (a *App[RT, C]) startGeneration(rt *RT) *generation[RT] {
	parent := a.serveCtx
	if parent == nil {
		parent = context.Background()
	}
	gctx, cancel := context.WithCancel(parent)
	gen := &generation[RT]{rt: rt, ctx: gctx, cancel: cancel, done: make(chan struct{})}
	// 后台资源（预热池/健康探测/规则源刷新）绑定应用级 ctx：其寿命 =
	// 实例寿命，由应用级关停（CloseResources）终结，不随代际结束而
	// 停止——否则热加载复用的实例（restore 回滚路径共享同一指针）
	// 后台循环会被 gen.cancel() 永久停摆。
	a.opts.Port.StartResources(rt, parent)
	svc := a.opts.Port.Services(rt)
	// 显式三段计数：入站 + 运维端点 + 控制面（零值 = 无，不计数不 spawn）。
	// 先计数后 spawn（done 关闭不早于计数，避免 Add-after-Wait 竞态）。
	services := len(svc.Inbounds) + 1
	if svc.Control.Serve != nil {
		services++
	}
	gen.wg.Add(services)
	for i := range svc.Inbounds {
		s := svc.Inbounds[i]
		go func() {
			defer gen.wg.Done()
			if err := s.Serve(gctx); err != nil && gctx.Err() == nil && parent.Err() == nil {
				a.fail(fmt.Errorf("%s: inbound %s: %w", a.opts.Name, s.Kind, err))
			}
		}()
	}
	go func() {
		defer gen.wg.Done()
		if err := svc.Admin.Serve(gctx); err != nil && gctx.Err() == nil && parent.Err() == nil {
			a.fail(fmt.Errorf("%s: admin endpoint: %w", a.opts.Name, err))
		}
	}()
	if svc.Control.Serve != nil {
		s := svc.Control
		go func() {
			defer gen.wg.Done()
			if err := s.Serve(gctx); err != nil && gctx.Err() == nil && parent.Err() == nil {
				a.fail(fmt.Errorf("%s: control endpoint: %w", a.opts.Name, err))
			}
		}()
	}
	go func() {
		gen.wg.Wait()
		close(gen.done)
	}()
	a.gen.Store(gen)
	return gen
}

// fail 记录首个致命服务错误并触发应用级关停（全部代际随之排空）。
func (a *App[RT, C]) fail(err error) {
	a.errMu.Lock()
	if a.firstErr == nil {
		a.firstErr = err
	}
	a.errMu.Unlock()
	if a.appCancel != nil {
		a.appCancel()
	}
}

func (a *App[RT, C]) firstError() error {
	a.errMu.Lock()
	defer a.errMu.Unlock()
	return a.firstErr
}

// Serving 原子读报告应用是否在服务中（测试接缝与重载判定共用）。
func (a *App[RT, C]) Serving() bool { return a.serving.Load() }

// Reload 应用一份新配置（重载流水线）：先完整构建新运行时，全部成功后
// 原子切换（先停旧监听再绑新监听，见 switchTo），旧快照排空。任何失败都
// 返回错误并保持旧配置在原端口继续服务——配置错误不会波及线上。
func (a *App[RT, C]) Reload(next C) error {
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()
	if a.closing.Load() || (a.serveCtx != nil && a.serveCtx.Err() != nil) || a.shuttingDown() {
		a.notifyReloadResult(false)
		return fmt.Errorf("%s: shutting down; reload ignored", a.opts.Name)
	}

	cur := a.live.Load()
	rt, err := a.opts.Assemble(next, cur)
	if err != nil {
		a.notifyReloadResult(false)
		return fmt.Errorf("%s: build new configuration: %w", a.opts.Name, err)
	}
	if err := a.switchTo(cur, rt); err != nil {
		a.notifyReloadResult(false)
		return err
	}

	if a.opts.OnReloaded != nil {
		a.opts.OnReloaded(next)
	}
	a.notifyReloadResult(true)
	return nil
}

// notifyReloadResult 记账一次重载尝试（成功 / 失败各恰一次）；钩子为 nil
// 时跳过（组装根未注入记账回调）。
func (a *App[RT, C]) notifyReloadResult(success bool) {
	if a.opts.OnReloadResult != nil {
		a.opts.OnReloadResult(success)
	}
}

// shuttingDown 报告当前代际是否已进入关停（排空中拒绝重载）。
func (a *App[RT, C]) shuttingDown() bool {
	if gen := a.gen.Load(); gen != nil {
		return gen.ctx.Err() != nil
	}
	return false
}

// switchTo 原子切换运行时（reloadMu 持有）：
//  1. 停旧：先取消旧代际 ctx（触发既有 drain/force 语义——session/http
//     机械会自行关闭监听并排空存量），再同步关闭旧监听释放端口；
//  2. 绑新：旧监听已停，同端口可重绑；任何失败回滚——关闭新运行时刚绑定
//     的监听与新建资源，用旧运行时保存的入站配置按其自身已解析地址端口
//     稳定地重建旧监听并恢复服务（最终效果：reload 失败时旧配置仍在原
//     端口继续服务，:0 入站不迁移端口）；回滚也失败时
//     fail-closed（fail → 应用级关停，Serve 返回，进程交由进程管理器重启）；
//  3. 提交：新快照上线（新代际），被替换的旧资源释放，旧存量连接排空。
func (a *App[RT, C]) switchTo(cur, next *RT) error {
	if gen := a.gen.Load(); gen != nil && gen.rt == cur {
		gen.cancel()
	}
	a.opts.Port.CloseListeners(cur)

	if err := a.opts.Port.Bind(next, cur); err != nil {
		a.opts.Port.CloseListeners(next)
		// 回滚清理只关新运行时（next）新建的资源，旧运行时（cur）零影响。
		a.opts.Port.CloseOwned(cur, next)
		if rerr := a.restore(cur); rerr != nil {
			if a.opts.OnRollbackFailed != nil {
				a.opts.OnRollbackFailed(rerr)
			}
			// Fail-closed：零监听存活是不可服务状态——记录首个致命错误并触发
			// 应用级关停，Serve 随之返回、进程按现有关停流程退出，交由进程
			// 管理器重启。
			a.fail(fmt.Errorf("%s: reload rollback failed: %w", a.opts.Name, rerr))
			return fmt.Errorf("%s: bind new configuration: %v; rollback failed: %w", a.opts.Name, err, rerr)
		}
		return fmt.Errorf("%s: bind new configuration: %w", a.opts.Name, err)
	}

	a.live.Store(next)
	if a.serving.Load() {
		a.startGeneration(next)
	}
	a.opts.Port.ReleaseReplaced(cur, next)
	return nil
}

// restore 在绑定失败后恢复旧配置服务：按旧运行时（cur）自身已解析的监听
// 地址重绑全部监听（previous=cur 的端口稳定重绑：:0 入站回滚后保持原监听
// 地址，与 switchTo 成功路径 Bind(next, cur) 的同端口语义一致；固定端口
// 按配置重绑行为不变），并重新上线（旧组件全部存活——切换失败路径只关闭
// 了新运行时新建的资源）。cur 的已解析地址在 CloseListeners 之后仍可读取
// （入站 Addr 闭包持有已绑定监听，net.Listener 关闭后 Addr 仍返回原地址，
// 成功路径在同样时序下依赖同一性质）。恢复代际必须经 Clone 浅拷贝上线：
// 旧代际（及其服务协程闭包）仍持有原指针，Store 原 rt 会与旧代际共享同一
// 快照身份。
func (a *App[RT, C]) restore(cur *RT) error {
	if err := a.opts.Port.Bind(cur, cur); err != nil {
		return err
	}
	if a.serving.Load() {
		restored := a.opts.Port.Clone(cur)
		a.live.Store(restored)
		a.startGeneration(restored)
	}
	return nil
}

// ReloadFile 读取、解析并应用配置文件（path 与启动时相同）。解析失败与
// 构建失败一样保持旧配置继续服务，并且每次尝试（无论失败在哪一步）都
// 恰好记账一次（OnReloadResult）。
func (a *App[RT, C]) ReloadFile(path, levelOverride string) error {
	cfg, err := a.opts.Load(path, levelOverride)
	if err != nil {
		a.notifyReloadResult(false)
		return err
	}
	return a.Reload(cfg)
}
