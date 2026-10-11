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

func TestControlSwapsLevelAndFormat(t *testing.T) {
	var buf bytes.Buffer
	logger, ctrl := NewControlWithWriter(&buf, "info", FormatJSON)

	logger.Info("first", "key", "value")
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "{") {
		t.Fatalf("initial format should be JSON: %q", buf.String())
	}

	// 切换格式：同一 logger 的后续输出立即使用新格式。
	buf.Reset()
	ctrl.SetFormat(FormatText)
	logger.Info("second", "key", "value")
	out := buf.String()
	if strings.HasPrefix(strings.TrimSpace(out), "{") || !strings.Contains(out, "key=value") {
		t.Fatalf("format swap did not take effect: %q", out)
	}

	// 切换级别：低于级别的日志被抑制，提高级别后恢复可见。
	buf.Reset()
	ctrl.SetLevel("error")
	if logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info should be disabled after switching to error")
	}
	logger.Info("suppressed")
	logger.Error("visible")
	if strings.Contains(buf.String(), "suppressed") || !strings.Contains(buf.String(), "visible") {
		t.Fatalf("level swap did not take effect: %q", buf.String())
	}

	// 非法值回退：级别回退 info、格式回退 json。
	buf.Reset()
	ctrl.SetLevel("nonsense")
	ctrl.SetFormat("nonsense")
	logger.Info("fallback", "key", "value")
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "{") {
		t.Fatalf("unknown format should fall back to JSON: %q", buf.String())
	}
	if ctrl.LevelVar().Level() != slog.LevelInfo {
		t.Fatalf("unknown level should fall back to info, got %v", ctrl.LevelVar().Level())
	}
}

func TestControlSwapKeepsDerivedLoggerAttrsAndGroups(t *testing.T) {
	var buf bytes.Buffer
	logger, ctrl := NewControlWithWriter(&buf, "info", FormatJSON)
	child := logger.With("component", "relay").WithGroup("outer")

	child.Info("before", "k", "v")
	ctrl.SetFormat(FormatJSON) // 触发一次底层 handler 替换
	child.Info("after", "k", "v")

	dec := json.NewDecoder(&buf)
	for _, want := range []string{"before", "after"} {
		var record map[string]any
		if err := dec.Decode(&record); err != nil {
			t.Fatalf("decode %s record: %v", want, err)
		}
		if record["component"] != "relay" {
			t.Fatalf("%s record lost bound attrs: %v", want, record)
		}
		outer, ok := record["outer"].(map[string]any)
		if !ok || outer["k"] != "v" {
			t.Fatalf("%s record lost bound group: %v", want, record)
		}
	}
}

func TestControlNilSafety(t *testing.T) {
	var nilCtrl *Control
	nilCtrl.SetLevel("debug")
	nilCtrl.SetFormat(FormatText)
	if nilCtrl.LevelVar() != nil {
		t.Fatal("nil control must return nil LevelVar")
	}
	// 与 nil 控制器组装的应用：/log/level 端点不可用（404），其它端点不受影响。
	if h := LevelHandler(nil, nilCtrl.LevelVar()); h == nil {
		t.Fatal("handler must not be nil")
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
	req := httptest.NewRequest(http.MethodPut, "/log/level?level=debug", nil)
	req.RemoteAddr = "127.0.0.1:34567" // 状态变更仅接受环回来源
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
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
	req = httptest.NewRequest(http.MethodPut, "/log/level?level=error", nil)
	req.RemoteAddr = "127.0.0.1:34567"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
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
	req = httptest.NewRequest(http.MethodPut, "/log/level?level=verbose", nil)
	req.RemoteAddr = "127.0.0.1:34567"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid level status = %d, want 400", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/log/level", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, PUT" {
		t.Fatalf("POST = %d Allow=%q", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestLevelHandlerRemotePutForbidden(t *testing.T) {
	_, lv := newWithWriter(&bytes.Buffer{}, "info", FormatJSON)
	h := LevelHandler(nil, lv)

	// 远程 GET（只读）允许。
	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	req.RemoteAddr = "203.0.113.5:45678"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"level":"info"`) {
		t.Fatalf("remote GET = %d %q, want 200 info", rec.Code, rec.Body.String())
	}

	// 远程 PUT（状态变更）一律 403，级别保持不变。
	req = httptest.NewRequest(http.MethodPut, "/log/level?level=debug", nil)
	req.RemoteAddr = "203.0.113.5:45678"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("remote PUT = %d %q, want 403", rec.Code, rec.Body.String())
	}
	if lv.Level() != slog.LevelInfo {
		t.Fatalf("level = %v, want unchanged info", lv.Level())
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
