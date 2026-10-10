// Command proxy-server 是远端出口：监听 Trojan（over TLS）隧道，
// 校验口令并转发到目标站点。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/serverapp"
	"github.com/OopsOo0ps/proxy/pkg/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	configPath := flag.String("config", "", "path to server config file (YAML)")
	logLevel := flag.String("log-level", "", "override log level from config: debug|info|warn|error")
	flag.Parse()

	if *showVersion {
		fmt.Printf("proxy-server %s\n", version.Get())
		return
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "proxy-server: -config is required")
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		fatal(err)
	}
	if *logLevel != "" {
		cfg.Log.Level = *logLevel
	}

	info := version.Get()
	logger, logCtrl := logging.NewControl(cfg.Log.Level, cfg.Log.Format)
	logger.Info("starting proxy-server",
		"version", info.Version,
		"commit", info.Commit,
		"platform", info.Platform,
	)

	app, err := serverapp.New(cfg, logger, logCtrl)
	if err != nil {
		fatal(err)
	}
	if err := app.Listen(); err != nil {
		fatal(err)
	}
	logger.Info("listening",
		"tunnel", app.TunnelAddr(),
		"metrics", app.MetricsAddr(),
		"users", len(cfg.Users),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGHUP 重新加载配置文件：先解析校验，失败保持旧配置继续服务；
	// 成功则原子生效（新连接使用新凭据与新证书）。
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
func reloadConfig(app *serverapp.App, path, logLevelOverride string, logger *slog.Logger) {
	cfg, err := config.LoadServer(path)
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
	fmt.Fprintf(os.Stderr, "proxy-server: %v\n", err)
	os.Exit(1)
}
