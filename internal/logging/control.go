// 运行时可调整的日志控制：级别与格式都支持热切换。
//
// 背景：slog.Logger 的 handler 在构造后不可替换，而配置热加载需要
// 在运行期切换日志格式（json / text）。controlHandler 以原子指针
// 持有当前底层 handler，切换格式时整体替换；通过 With 派生的子
// logger 携带的字段与分组同样跟随切换。
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
)

// Control 是日志级别与格式的运行期控制器。通过 NewControl 创建；
// 所有方法对 nil 接收者安全。
type Control struct {
	lv    *slog.LevelVar
	state *controlState
	w     io.Writer
}

// controlState 是各 controlHandler 共享的底层 handler 槽位。
type controlState struct {
	inner atomic.Pointer[slog.Handler]
	gen   atomic.Uint64 // 每次替换自增，供派生 handler 失效本地缓存
}

func (s *controlState) swap(h slog.Handler) {
	s.inner.Store(&h)
	s.gen.Add(1)
}

// NewControl 创建支持运行期调整级别与格式的 logger 及其控制器。
// 非法级别回退 info、非法格式回退 json，语义与 New 一致。
func NewControl(level, format string) (*slog.Logger, *Control) {
	return newControl(os.Stderr, level, format)
}

// NewControlWithWriter 与 NewControl 行为一致，但允许指定输出目标（便于测试）。
func NewControlWithWriter(w io.Writer, level, format string) (*slog.Logger, *Control) {
	return newControl(w, level, format)
}

func newControl(w io.Writer, level, format string) (*slog.Logger, *Control) {
	lv := new(slog.LevelVar)
	lv.Set(parseLevel(level))
	c := &Control{lv: lv, state: new(controlState), w: w}
	c.state.swap(newHandler(w, lv, format))
	return slog.New(&controlHandler{state: c.state}), c
}

// SetLevel 切换日志级别（debug / info / warn / error，未知值回退 info）。
func (c *Control) SetLevel(level string) {
	if c == nil {
		return
	}
	c.lv.Set(parseLevel(level))
}

// SetFormat 切换日志格式（json / text，未知值回退 json）。
func (c *Control) SetFormat(format string) {
	if c == nil {
		return
	}
	c.state.swap(newHandler(c.w, c.lv, format))
}

// LevelVar 返回级别控制器，供 /log/level 端点使用；nil 接收者返回 nil。
func (c *Control) LevelVar() *slog.LevelVar {
	if c == nil {
		return nil
	}
	return c.lv
}

// controlHandler 是挂在 logger 上的固定 handler：携带字段与分组，
// 实际输出委托给当前底层 handler。
type controlHandler struct {
	state *controlState
	// ops 按调用顺序记录 WithAttrs / WithGroup，重建时按同样顺序重放，
	// 保证与 slog 原生 handler 完全一致的分组语义。
	ops   []controlOp
	cache atomic.Pointer[resolvedHandler]
}

// controlOp 是一次 WithAttrs 或 WithGroup 调用。
type controlOp struct {
	group string
	attrs []slog.Attr
}

// resolvedHandler 缓存“当前底层 handler + 本节点字段/分组”的组合结果，
// 代际（gen）变化时失效重建，避免每条日志重复 WithAttrs 分配。
type resolvedHandler struct {
	gen uint64
	h   slog.Handler
}

func (h *controlHandler) resolve() slog.Handler {
	gen := h.state.gen.Load()
	if cached := h.cache.Load(); cached != nil && cached.gen == gen {
		return cached.h
	}
	inner := *h.state.inner.Load()
	for _, op := range h.ops {
		if op.group != "" {
			inner = inner.WithGroup(op.group)
		} else if len(op.attrs) > 0 {
			inner = inner.WithAttrs(op.attrs)
		}
	}
	h.cache.Store(&resolvedHandler{gen: gen, h: inner})
	return inner
}

func (h *controlHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.resolve().Enabled(ctx, level)
}

func (h *controlHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.resolve().Handle(ctx, r)
}

func (h *controlHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	ops := make([]controlOp, 0, len(h.ops)+1)
	ops = append(ops, h.ops...)
	ops = append(ops, controlOp{attrs: append([]slog.Attr(nil), attrs...)})
	return &controlHandler{state: h.state, ops: ops}
}

func (h *controlHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	ops := make([]controlOp, 0, len(h.ops)+1)
	ops = append(ops, h.ops...)
	ops = append(ops, controlOp{group: name})
	return &controlHandler{state: h.state, ops: ops}
}
