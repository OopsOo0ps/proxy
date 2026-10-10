// Package logging 为各可执行程序提供统一的日志初始化。
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New 按级别创建输出到标准错误的 slog.Logger。
// 合法级别：debug、info、warn、error；未知取值回退为 info。
func New(level string) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLevel(level),
	}))
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
