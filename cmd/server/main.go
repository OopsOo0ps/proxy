// Command proxy-server 是远端出口：监听 Trojan（over TLS）隧道，
// 校验口令并转发到目标站点。
package main

import (
	"context"
	"flag"
	"fmt"
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
	logger, logLevelVar := logging.New(cfg.Log.Level, cfg.Log.Format)
	logger.Info("starting proxy-server",
		"version", info.Version,
		"commit", info.Commit,
		"platform", info.Platform,
	)

	app, err := serverapp.New(cfg, logger, logLevelVar)
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

	if err := app.Serve(ctx); err != nil {
		fatal(err)
	}
	logger.Info("shutdown complete")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "proxy-server: %v\n", err)
	os.Exit(1)
}
