// Command proxy-client 是本机代理入口：
// 提供 HTTP/HTTPS 与 SOCKS5 入站，按规则直连或经出口节点隧道转发。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/OopsOo0ps/proxy/internal/clientapp"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/pkg/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	configPath := flag.String("config", "", "path to client config file (YAML)")
	logLevel := flag.String("log-level", "", "override log level from config: debug|info|warn|error")
	flag.Parse()

	if *showVersion {
		fmt.Printf("proxy-client %s\n", version.Get())
		return
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "proxy-client: -config is required")
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.LoadClient(*configPath)
	if err != nil {
		fatal(err)
	}
	if *logLevel != "" {
		cfg.Log.Level = *logLevel
	}

	info := version.Get()
	logger, logCtrl := logging.NewControl(cfg.Log.Level, cfg.Log.Format)
	logger.Info("starting proxy-client",
		"version", info.Version,
		"commit", info.Commit,
		"platform", info.Platform,
	)

	app, err := clientapp.New(cfg, logger, logCtrl)
	if err != nil {
		fatal(err)
	}
	if err := app.Listen(); err != nil {
		fatal(err)
	}
	fields := []any{
		"http", app.HTTPAddr(),
		"socks5", app.SOCKS5Addr(),
		"metrics", app.MetricsAddr(),
		"nodes", len(cfg.Nodes),
		"routing_default", cfg.Routing.Default,
	}
	if addr := app.DNSAddr(); addr != "" {
		fields = append(fields, "dns", addr, "dns_remote", cfg.DNS.EffectiveRemote())
	}
	logger.Info("listening", fields...)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGHUP 重新加载配置文件：先解析校验，失败保持旧配置继续服务；
	// 成功则原子生效（新连接使用新配置）。
	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)
	defer signal.Stop(reloadCh)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reloadCh:
				reloadConfig(app, *configPath, *logLevel, logger)
			}
		}
	}()

	if err := app.Serve(ctx); err != nil {
		fatal(err)
	}
	logger.Info("shutdown complete")
}

// reloadConfig 读取并校验配置文件后交给应用原子生效。
// 任何失败都只记录错误：进程保持旧配置继续服务，配置错误不影响线上。
func reloadConfig(app *clientapp.App, path, logLevelOverride string, logger *slog.Logger) {
	cfg, err := config.LoadClient(path)
	if err != nil {
		logger.Error("config reload failed; keeping current configuration", "error", err)
		return
	}
	// 启动参数 -log-level 是显式覆盖：重载时同样优先于文件值。
	if logLevelOverride != "" {
		cfg.Log.Level = logLevelOverride
	}
	if err := app.Reload(cfg); err != nil {
		logger.Error("config reload failed; keeping current configuration", "error", err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "proxy-client: %v\n", err)
	os.Exit(1)
}
