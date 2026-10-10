package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewFiltersBelowConfiguredLevel(t *testing.T) {
	logger := New("warn", FormatJSON)
	if logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info should be disabled at warn level")
	}
	if !logger.Enabled(context.Background(), slog.LevelWarn) {
		t.Fatal("warn should be enabled at warn level")
	}
}

func TestNewUnknownLevelFallsBackToInfo(t *testing.T) {
	logger := New("nonsense", FormatJSON)
	if !logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info should be enabled by default")
	}
	if logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("debug should be disabled by default")
	}
}

func TestNewJSONFormatEmitsStructuredLog(t *testing.T) {
	var buf bytes.Buffer
	logger := newWithWriter(&buf, "info", FormatJSON)
	logger.Info("request completed", "request_id", "abc", "duration", "1ms")

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("log output is not valid JSON: %v (%q)", err, buf.String())
	}
	if record["request_id"] != "abc" {
		t.Fatalf("request_id = %v, want abc", record["request_id"])
	}
}

func TestNewTextFormatEmitsPlainText(t *testing.T) {
	var buf bytes.Buffer
	logger := newWithWriter(&buf, "info", FormatText)
	logger.Info("hello", "key", "value")

	out := buf.String()
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Fatalf("text format should not emit JSON: %q", out)
	}
	if !strings.Contains(out, "key=value") {
		t.Fatalf("text output missing key=value: %q", out)
	}
}

func TestNewUnknownFormatFallsBackToJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := newWithWriter(&buf, "info", "nonsense")
	logger.Info("hello", "key", "value")
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "{") {
		t.Fatalf("unknown format should fall back to JSON, got %q", buf.String())
	}
}

func TestNewRequestIDFormat(t *testing.T) {
	id := NewRequestID()
	if len(id) != 16 {
		t.Fatalf("request id length = %d, want 16", len(id))
	}
	for _, r := range id {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("request id %q contains non-hex character %q", id, r)
		}
	}
	if again := NewRequestID(); again == id {
		t.Fatalf("request ids should be unique, got %q twice", id)
	}
}

func TestRequestIDContextRoundTrip(t *testing.T) {
	ctx := WithRequestID(context.Background(), "deadbeef")
	if got := RequestIDFrom(ctx); got != "deadbeef" {
		t.Fatalf("RequestIDFrom = %q, want deadbeef", got)
	}
	if got := RequestIDFrom(context.Background()); got != "" {
		t.Fatalf("RequestIDFrom(empty ctx) = %q, want empty", got)
	}
}
