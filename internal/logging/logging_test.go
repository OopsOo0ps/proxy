package logging

import (
	"context"
	"log/slog"
	"testing"
)

func TestNewFiltersBelowConfiguredLevel(t *testing.T) {
	logger := New("warn")
	if logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info should be disabled at warn level")
	}
	if !logger.Enabled(context.Background(), slog.LevelWarn) {
		t.Fatal("warn should be enabled at warn level")
	}
}

func TestNewUnknownLevelFallsBackToInfo(t *testing.T) {
	logger := New("nonsense")
	if !logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info should be enabled by default")
	}
	if logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("debug should be disabled by default")
	}
}
