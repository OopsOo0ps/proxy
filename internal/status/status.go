// Package status 提供两个运维端点：/health（存活与依赖检查）与 /stats（运行时状态快照）。
//
// 设计要点：
//   - 启动时间、版本、依赖检查与运行时快照由组装方（clientapp / serverapp）注入，
//     两个进程各自裁剪输出内容，也便于单元测试；
//   - 内存占用每次请求时从 runtime.MemStats 直接读取，无需注入；
//   - /metrics 与 /log/level 处理器同样由组装方注入（本包不 import metrics，
//     L4 组装根是唯一可同时触达二者的包）；端点与它们共用 api.listen 监听，
//     不单独配置端口。
package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// Options 是 New 的参数。
type Options struct {
	// Version 是构建版本号，出现在 /stats 中。
	Version string
	// Start 是启动时间，用于计算 uptime；零值表示取构造时刻。
	Start time.Time
	// Checks 是依赖健康检查；任一返回非 nil 错误时 /health 返回 503。
	Checks []func() error
	// Runtime 返回运行时快照（连接数、上游状态）；nil 表示空快照。
	Runtime func() Runtime
}

// Status 依据 Options 生成 /health 与 /stats 处理器。
type Status struct {
	version string
	start   time.Time
	checks  []func() error
	runtime func() Runtime
}

// New 创建 Status。
func New(opts Options) *Status {
	start := opts.Start
	if start.IsZero() {
		start = time.Now()
	}
	return &Status{
		version: opts.Version,
		start:   start,
		checks:  opts.Checks,
		runtime: opts.Runtime,
	}
}

// Connections 是按入站协议统计的活跃连接数。未使用的协议字段省略，total 恒有。
type Connections struct {
	HTTP   int64 `json:"http,omitempty"`
	SOCKS5 int64 `json:"socks5,omitempty"`
	Tunnel int64 `json:"tunnel,omitempty"`
	Total  int64 `json:"total"`
}

// Upstream 是单个出口节点的状态（仅 proxy-client 输出）。
type Upstream struct {
	Addr              string  `json:"addr"`
	Healthy           bool    `json:"healthy"`            // 当前是否可接流量（未摘除且不在冷却中）
	Fails             int     `json:"fails"`              // 连续真实拨号失败次数
	CooldownRemaining float64 `json:"cooldown_remaining"` // 冷却剩余秒数
	Removed           bool    `json:"removed"`            // 是否被主动健康检查摘除
	ProbeFails        int     `json:"probe_fails"`        // 当前连续探测失败次数
	Idle              int     `json:"idle"`               // 空闲预热连接数；未启用连接池时为 0
}

// Memory 是进程内存与运行时统计。
type Memory struct {
	AllocBytes uint64 `json:"alloc_bytes"` // 当前堆分配字节数
	SysBytes   uint64 `json:"sys_bytes"`   // 从操作系统获取的内存字节数
	NumGC      uint32 `json:"num_gc"`      // 完成的 GC 次数
	Goroutines int    `json:"goroutines"`  // 当前协程数
}

// Ruleset 是分流规则源的运行时状态（仅 proxy-client 配置了规则源时输出）。
type Ruleset struct {
	Source      string  `json:"source"`                    // file | url
	Target      string  `json:"target"`                    // 规则文件路径或 URL
	Refresh     float64 `json:"refresh_seconds,omitempty"` // URL 定时刷新周期（秒）；0 = 仅启动拉取一次
	Loaded      bool    `json:"loaded"`                    // 是否已有成功加载的规则
	Rules       int     `json:"rules"`                     // 当前生效的规则条数
	LastSuccess string  `json:"last_success,omitempty"`    // 最近一次成功加载时间（RFC3339）
	LastError   string  `json:"last_error,omitempty"`      // 最近一次失败原因；成功后清空
}

// Runtime 是运行时可变部分的快照。
type Runtime struct {
	Connections Connections
	Upstreams   []Upstream
	Ruleset     *Ruleset
	Limit       *Limit
}

// Limit 是连接上限与拒绝统计（仅配置了连接上限时输出）。
type Limit struct {
	MaxConnections int    `json:"max_connections"` // 0 = 不限制
	Current        int    `json:"current"`         // 当前占用
	Rejected       uint64 `json:"rejected"`        // 累计被拒绝的连接数
}

// healthResponse 是 /health 的响应体。
type healthResponse struct {
	Status string  `json:"status"` // ok | unavailable
	Uptime float64 `json:"uptime"` // 秒
	Reason string  `json:"reason,omitempty"`
}

// statsResponse 是 /stats 的响应体。
type statsResponse struct {
	Version     string      `json:"version"`
	Uptime      float64     `json:"uptime"` // 秒
	Connections Connections `json:"connections"`
	Upstreams   []Upstream  `json:"upstreams,omitempty"`
	Ruleset     *Ruleset    `json:"ruleset,omitempty"`
	Limit       *Limit      `json:"limit,omitempty"`
	Memory      Memory      `json:"memory"`
}

// Health 返回 /health 处理器：依赖全部健康时返回 200，任一不可用时返回 503。
func (s *Status) Health() http.Handler {
	if s == nil {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowGET(w, r) {
			return
		}
		resp := healthResponse{Status: "ok", Uptime: Seconds(time.Since(s.start))}
		var reasons []string
		for _, check := range s.checks {
			if err := check(); err != nil {
				reasons = append(reasons, err.Error())
			}
		}
		code := http.StatusOK
		if len(reasons) > 0 {
			resp.Status = "unavailable"
			resp.Reason = strings.Join(reasons, "; ")
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, resp)
	})
}

// Stats 返回 /stats 处理器：连接数、上游状态、规则源状态与内存占用快照。
func (s *Status) Stats() http.Handler {
	if s == nil {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowGET(w, r) {
			return
		}
		var rt Runtime
		if s.runtime != nil {
			rt = s.runtime()
		}
		writeJSON(w, http.StatusOK, statsResponse{
			Version:     s.version,
			Uptime:      Seconds(time.Since(s.start)),
			Connections: rt.Connections,
			Upstreams:   rt.Upstreams,
			Ruleset:     rt.Ruleset,
			Limit:       rt.Limit,
			Memory:      readMemory(),
		})
	})
}

// Seconds 把时长转换为秒数（毫秒精度），供 JSON 输出使用。
func Seconds(d time.Duration) float64 {
	return math.Round(d.Seconds()*1000) / 1000
}

// readMemory 读取当前进程的内存与运行时统计。
func readMemory() Memory {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return Memory{
		AllocBytes: ms.Alloc,
		SysBytes:   ms.Sys,
		NumGC:      ms.NumGC,
		Goroutines: runtime.NumGoroutine(),
	}
}

// allowGET 校验请求方法；非 GET 返回 405 并带上 Allow 头。
func allowGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	w.Header().Set("Allow", http.MethodGet)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

// writeJSON 输出 JSON 响应（不转义 HTML，附加换行便于命令行阅读）。
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// —— 运维端点宿主（组装根的 Runtime.Admin，设计文档 §8.2）——

// ServerOptions 是 NewServer 的参数；Metrics 与 LogLevel 处理器由组装根注入
// （本包不 import metrics / logging，依赖方向由 arch 守护约束）。
type ServerOptions struct {
	// Version 是构建版本号，出现在 /stats 中。
	Version string
	// Start 是启动时间，用于计算 uptime；零值表示取构造时刻。
	Start time.Time
	// Checks 是依赖健康检查；任一返回非 nil 错误时 /health 返回 503。
	Checks []func() error
	// Runtime 返回运行时快照（连接数、上游状态）；nil 表示空快照。
	Runtime func() Runtime
	// Metrics 是 /metrics 处理器（组装根注入）；nil 时该端点 404。
	Metrics http.Handler
	// LogLevel 是 /log/level 处理器（组装根注入）；nil 时该端点 404。
	LogLevel http.Handler
}

// Server 是运维端点（/metrics /health /stats /log/level）的宿主：
// 组装根注入各处理器，本包承载监听与服务生命周期。监听绑定属于组装根的
// 构建步骤（不变量 3），Bind 失败由调用方决定整体回滚。
type Server struct {
	handler http.Handler
	ln      net.Listener
	srv     *http.Server
}

// NewServer 组装运维端点处理器（零副作用；绑定监听见 Bind）。
func NewServer(opts ServerOptions) *Server {
	mux := http.NewServeMux()
	if opts.Metrics != nil {
		mux.Handle("/metrics", opts.Metrics)
	} else {
		mux.Handle("/metrics", http.NotFoundHandler())
	}
	st := New(Options{
		Version: opts.Version,
		Start:   opts.Start,
		Checks:  opts.Checks,
		Runtime: opts.Runtime,
	})
	mux.Handle("/health", st.Health())
	mux.Handle("/stats", st.Stats())
	if opts.LogLevel != nil {
		mux.Handle("/log/level", opts.LogLevel)
	} else {
		mux.Handle("/log/level", http.NotFoundHandler())
	}
	return &Server{handler: mux}
}

// Bind 绑定运维端点监听；addr 为空表示不启用（空操作）。
// 重复 Bind 前须先 Close（旧监听仍持有时会绑定失败）。
func (s *Server) Bind(addr string) error {
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("status: listen %s: %w", addr, err)
	}
	s.ln = ln
	s.srv = &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return nil
}

// Serve 阻塞服务直到 ctx 取消（3s 内排空在途请求）；未绑定时立即返回 nil。
func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.srv == nil {
		return nil
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.srv.Shutdown(shutdownCtx)
		case <-done:
		}
	}()
	err := s.srv.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close 关闭监听（停止接受新连接）；幂等，重置绑定状态以便失败恢复路径重绑。
func (s *Server) Close() error {
	if s == nil || s.ln == nil {
		return nil
	}
	err := s.ln.Close()
	s.ln = nil
	s.srv = nil
	return err
}

// Addr 返回绑定地址；未绑定时为空串。
func (s *Server) Addr() string {
	if s == nil || s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}
