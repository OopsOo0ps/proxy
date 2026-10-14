package ruleset

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/OopsOo0ps/proxy/internal/version"
)

// maxRedirects 是单次拉取允许的最大重定向跳数（与 net/http 缺省一致）。
const maxRedirects = 10

// fetchConfig 是远程规则拉取的固定约束。
type fetchConfig struct {
	client   *http.Client
	maxBytes int64
}

// resolveFetchConfig 依据 Options 解析拉取约束（缺省 15s / 8 MiB）。
func resolveFetchConfig(opts Options) fetchConfig {
	timeout := opts.FetchTimeout
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	maxBytes := opts.MaxFetchBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxFetchBytes
	}
	client := opts.fetchClient
	if client == nil {
		client = &http.Client{
			Timeout:       timeout,
			CheckRedirect: rulesRedirectChecker,
		}
	}
	return fetchConfig{
		client:   client,
		maxBytes: maxBytes,
	}
}

// rulesRedirectChecker 是拉取客户端的重定向守卫（CheckRedirect）：拦截
// https → http 的重定向降级（明文 http 仅允许环回地址，本地演示场景），
// 与 config 层的 URL 校验同一从严语义；并保留缺省的 10 跳上限。
func rulesRedirectChecker(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme == "http" && !isLoopbackHost(req.URL.Host) {
		return fmt.Errorf("redirect to plain http is only allowed for loopback addresses (got %q)", req.URL.String())
	}
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	return nil
}

// isLoopbackHost 判断 URL 的 Host（可能含端口、IPv6 需去括号）是否指向
// 本机环回；主机名（localhost 除外）按非环回处理（fail-closed）。本包为
// L2 不可依赖 config（L4），与 config 层的同名从严语义保持一致。
func isLoopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback()
}

// fetchRules 拉取远程规则内容：仅允许 http/https，校验状态码并限制响应体大小。
func (f fetchConfig) fetchRules(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid rules URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid rules URL %q: scheme must be http or https", rawURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid rules URL %q: missing host", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build rules request: %w", err)
	}
	req.Header.Set("User-Agent", "proxy-client/"+version.Get().Version)
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch rules: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("fetch rules: unexpected status %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch rules: read body: %w", err)
	}
	if int64(len(data)) > f.maxBytes {
		return nil, fmt.Errorf("fetch rules: response exceeds %d bytes limit", f.maxBytes)
	}
	return data, nil
}
