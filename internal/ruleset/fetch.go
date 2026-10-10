package ruleset

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/OopsOo0ps/proxy/pkg/version"
)

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
		client = &http.Client{Timeout: timeout}
	}
	return fetchConfig{
		client:   client,
		maxBytes: maxBytes,
	}
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
