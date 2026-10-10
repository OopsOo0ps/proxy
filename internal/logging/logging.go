// Package logging 为各可执行程序提供统一的日志初始化与请求关联 ID。
//
// 日志基于标准库 log/slog：默认输出结构化 JSON，字段命名与 1.6 号需求
// 保持一致（request_id / client_ip / upstream / duration 等）。
package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"strings"
)

// 日志输出格式。
const (
	FormatJSON = "json"
	FormatText = "text"
)

// requestIDKey 是 context 中请求 ID 的键类型（不导出，避免键冲突）。
type requestIDKey struct{}

// New 按级别与格式创建输出到标准错误的 slog.Logger。
//
// 合法级别：debug、info、warn、error，未知取值回退为 info；
// 合法格式：json、text，未知取值回退为 json（结构化日志优先）。
func New(level, format string) *slog.Logger {
	return newWithWriter(os.Stderr, level, format)
}

// newWithWriter 与 New 行为一致，但允许指定输出目标（便于测试）。
func newWithWriter(w io.Writer, level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var handler slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), FormatText) {
		handler = slog.NewTextHandler(w, opts)
	} else {
		handler = slog.NewJSONHandler(w, opts)
	}
	return slog.New(handler)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// NewRequestID 生成一次请求的关联 ID（16 位十六进制随机串）。
// 使用 crypto/rand，避免日志中的 request_id 可被猜测或碰撞。
func NewRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 在受支持平台上不会失败；兜底仍保证格式合法。
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// WithRequestID 把请求 ID 存入 context，供下游（如 HTTP 传输层）取用。
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFrom 从 context 中取出请求 ID；不存在时返回空字符串。
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}
