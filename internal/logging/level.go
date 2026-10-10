// 运行时日志级别端点：GET 查询当前级别，PUT 切换级别（debug/info/warn/error）。
// 与 /metrics、/stats 等运维端点一样不做鉴权，请仅在环回地址或防火墙之后暴露。
package logging

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// LevelName 返回 LevelVar 当前级别的配置写法（debug / info / warn / error）。
func LevelName(lv *slog.LevelVar) string {
	if lv == nil {
		return ""
	}
	switch lv.Level() {
	case slog.LevelDebug:
		return "debug"
	case slog.LevelWarn:
		return "warn"
	case slog.LevelError:
		return "error"
	default:
		return "info"
	}
}

// LevelHandler 返回日志级别端点（与 /metrics 共用运维监听）：
//
//	GET /log/level                -> 200 {"level":"info"}
//	PUT /log/level?level=debug    -> 200 {"level":"debug","previous":"info"}
//
// 非法级别返回 400；其它方法返回 405（Allow: GET, PUT）。
// lv 为 nil 时端点不可用（404）。
func LevelHandler(logger *slog.Logger, lv *slog.LevelVar) http.Handler {
	if lv == nil {
		return http.NotFoundHandler()
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeLevelJSON(w, http.StatusOK, map[string]string{"level": LevelName(lv)})
		case http.MethodPut:
			name := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level")))
			level, ok := parseLevelStrict(name)
			if !ok {
				writeLevelJSON(w, http.StatusBadRequest, map[string]string{
					"error": "invalid level: want debug, info, warn or error",
				})
				return
			}
			previous := LevelName(lv)
			// 先记录再生效：即使切到 error，这条变更凭证也应可见。
			logger.Info("log level changed", "from", previous, "to", name)
			lv.Set(level)
			writeLevelJSON(w, http.StatusOK, map[string]string{"level": name, "previous": previous})
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// parseLevelStrict 解析端点参数；只接受四档合法级别（大小写不敏感）。
func parseLevelStrict(name string) (slog.Level, bool) {
	switch name {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return 0, false
	}
}

// writeLevelJSON 输出 JSON 响应（不转义 HTML，附加换行便于命令行阅读）。
func writeLevelJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
