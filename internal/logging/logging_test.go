package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewFiltersBelowConfiguredLevel(t *testing.T) {
	logger, _ := New("warn", FormatJSON)
	if logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info should be disabled at warn level")
	}
	if !logger.Enabled(context.Background(), slog.LevelWarn) {
		t.Fatal("warn should be enabled at warn level")
	}
}

func TestNewUnknownLevelFallsBackToInfo(t *testing.T) {
	logger, _ := New("nonsense", FormatJSON)
	if !logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info should be enabled by default")
	}
	if logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("debug should be disabled by default")
	}
}

func TestNewJSONFormatEmitsStructuredLog(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := newWithWriter(&buf, "info", FormatJSON)
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
	logger, _ := newWithWriter(&buf, "info", FormatText)
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
	logger, _ := newWithWriter(&buf, "info", "nonsense")
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

func TestLevelHandler(t *testing.T) {
	var buf bytes.Buffer
	logger, lv := newWithWriter(&buf, "info", FormatJSON)
	h := LevelHandler(logger, lv)

	// GET 返回当前级别。
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/log/level", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"level":"info"`) {
		t.Fatalf("GET = %d %q", rec.Code, rec.Body.String())
	}

	// PUT 切换级别：响应含新旧级别，过滤立即生效，变更本身有日志凭证。
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/log/level?level=debug", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `"level":"debug"`) || !strings.Contains(body, `"previous":"info"`) {
		t.Fatalf("PUT = %d %q", rec.Code, body)
	}
	if lv.Level() != slog.LevelDebug {
		t.Fatalf("level = %v, want debug", lv.Level())
	}
	if !strings.Contains(buf.String(), "log level changed") {
		t.Fatalf("level change must be logged: %q", buf.String())
	}
	buf.Reset()
	logger.Debug("now visible")
	if !strings.Contains(buf.String(), "now visible") {
		t.Fatal("debug log should be visible after switching to debug")
	}

	// 切到 error 后 info/debug 被抑制，error 仍可见。
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/log/level?level=error", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT error = %d", rec.Code)
	}
	buf.Reset()
	logger.Info("hidden")
	logger.Error("visible")
	out := buf.String()
	if strings.Contains(out, "hidden") || !strings.Contains(out, "visible") {
		t.Fatalf("filtering after switching to error: %q", out)
	}

	// 非法级别与非法方法。
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/log/level?level=verbose", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid level status = %d, want 400", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/log/level", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, PUT" {
		t.Fatalf("POST = %d Allow=%q", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestLevelHandlerNilVarIsNotFound(t *testing.T) {
	rec := httptest.NewRecorder()
	LevelHandler(nil, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/log/level", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("nil level var = %d, want 404", rec.Code)
	}
	if LevelName(nil) != "" {
		t.Fatal("LevelName(nil) should be empty")
	}
}
