// Package session 统一入站协议的接受/排空生命周期（设计文档 §4.3）。
//
// 只承载 accept/drain 的机械部分：ctx 取消 → 停止接受（关闭 listener）→
// 存量连接在排空期限内自然结束 → 超时后强制断开。协议逻辑收敛在 ConnHandler
// 实现（握手、认证、拒绝路径与遥测事件发射都在协议侧），本包不认识任何协议
// 词汇与 Telemetry——新入站实现 ConnHandler 即免费获得背压闸、双 ctx 语义与
// 优雅排空。基于 net/http 的入站（httpproxy）排空路径无法套进手工循环，
// 保持独立，仅复用底部的完成日志辅助函数。
//
// 与关停信号的关系：机械层持有两个 ctx，语义显式分离——serveCtx 供 accept
// 循环感知关停（停止接受），connCtx 承载强制期限（drain 期存量连接继续处理，
// 仅期限到点被取消）。
package session

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/OopsOo0ps/proxy/internal/shutdown"
)

// DrainedConnections 是排空完成日志的默认文案（通用入站）。
const DrainedConnections = "shutdown: all in-flight connections drained"

// ConnHandler 是单条连接的协议逻辑：握手 → 认证 → 提取 Target → 拨号 →
// relay → 排空；拒绝路径（认证失败/路由拒绝/出站失败的协议响应字节）与
// Telemetry 事件的发射时机也在这里（由协议侧负责，机械层不感知）。
type ConnHandler interface {
	// ServeConn 处理一条已接受的连接；connCtx 承载强制断开期限
	//（排空超时后被取消），实现方据自身需要对它敏感。
	ServeConn(connCtx context.Context, conn net.Conn)
}

// Options 是 Serve 的行为参数。
type Options struct {
	// Gate 是并发闸检查（connlimit 注入）：返回 false 表示过载。
	// 在 accept 与握手之间检查；为 nil 时不检查。
	Gate func() bool
	// Reject 是过载拒绝的协议响应（协议包提供：HTTP 503 / SOCKS5 0xFF /
	// 直接关闭），Gate 判定为过载时对被拒连接调用一次；
	// 拒绝的观测（遥测事件）由该闭包负责发射。Gate 非 nil 时必填。
	Reject func(conn net.Conn)
	// Logger 关停日志；为 nil 时静默。
	Logger *slog.Logger
	// DrainTimeout 返回关停排空期限（热加载可变，故为 getter）。
	// 为 nil 时使用 shutdown.DefaultTimeout；非 nil 时返回值原样生效
	// （组件的默认值解析与校验在各自 getter 内完成，本包不做二次钳制）。
	DrainTimeout func() time.Duration
	// DrainedMessage 是排空完成日志的文案；现有文案逐字保留
	// （通用入站为 connections，隧道服务端为 tunnels），为空时使用默认文案。
	DrainedMessage string
}

// Serve 在 ln 上接受连接并逐个交给 handler 处理；serveCtx 取消后优雅关停：
// 先停止接受新连接，存量连接（connCtx）在排空期限内自然结束，超时后强制断开。
// Gate 在 accept 与握手之间检查，false 时调用 Reject 并继续接受后续连接。
func Serve(serveCtx context.Context, ln net.Listener, h ConnHandler, opts Options) error {
	if opts.Gate != nil && opts.Reject == nil {
		return errors.New("session: Gate requires Reject (protocol reject response must be provided)")
	}
	// connCtx 与关停信号解耦：收到关停后存量连接继续处理，
	// 只有超过排空期限（forceCancel）才被打断。
	connCtx, forceCancel := context.WithCancel(context.WithoutCancel(serveCtx))
	defer forceCancel()

	var wg sync.WaitGroup
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-serveCtx.Done():
			_ = ln.Close()
		case <-done:
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if serveCtx.Err() != nil {
				drain(opts, &wg, forceCancel)
				return nil
			}
			return err
		}
		if opts.Gate != nil && !opts.Gate() {
			opts.Reject(conn)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeConn(connCtx, conn)
		}()
	}
}

// drain 排空存量连接；超过排空期限后强制中断仍阻塞的连接。
// 两条关停日志（started/drained 或 timeout）的文案与字段由各入站逐字保留。
func drain(o Options, wg *sync.WaitGroup, forceCancel context.CancelFunc) {
	timeout := shutdown.DefaultTimeout
	if o.DrainTimeout != nil {
		timeout = o.DrainTimeout()
	}
	o.logger().Info("shutdown: stopped accepting new connections",
		"drain_timeout", timeout.String())
	if shutdown.Wait(wg, timeout, forceCancel) {
		o.logger().Info(o.drainedMessage())
		return
	}
	o.logger().Warn("shutdown: timeout exceeded, remaining connections closed")
}

// drainedMessage 返回排空完成日志文案（空值回退默认文案）。
func (o Options) drainedMessage() string {
	if o.DrainedMessage == "" {
		return DrainedConnections
	}
	return o.DrainedMessage
}

func (o Options) logger() *slog.Logger {
	if o.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return o.Logger
}

// RelayAttrs 组装双向转发完成日志的公共尾部字段（duration/duration_ms/
// bytes_up/bytes_down/result；relayErr 非 nil 时附 error）。三个转发型入站
// （httpproxy CONNECT / socks5 / trojan）共用，仅函数级复用、不含任何策略：
// elapsed 由调用方算好传入（同一值也用于遥测，保证口径一致），协议特有
// 字段（target/route/upstream 等）由调用方自行前缀。
func RelayAttrs(elapsed time.Duration, bytesUp, bytesDown int64, result string, relayErr error) []any {
	attrs := []any{
		"duration", elapsed.Round(time.Microsecond).String(),
		"duration_ms", elapsed.Milliseconds(),
		"bytes_up", bytesUp,
		"bytes_down", bytesDown,
		"result", result,
	}
	if relayErr != nil {
		attrs = append(attrs, "error", relayErr.Error())
	}
	return attrs
}
