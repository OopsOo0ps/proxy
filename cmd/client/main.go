// Command proxy-client 是本机代理入口：
// 提供 HTTP/HTTPS 与 SOCKS5 入站，按规则直连或经出口节点隧道转发。
package main

import (
	"context"
	"flag"
	"fmt"
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
				if err := app.ReloadFile(*configPath, *logLevel); err != nil {
					logger.Error("config reload failed; keeping current configuration", "error", err)
				}
			}
		}
	}()

	if err := app.Serve(ctx); err != nil {
		fatal(err)
	}
	logger.Info("shutdown complete")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "proxy-client: %v\n", err)
	os.Exit(1)
}
