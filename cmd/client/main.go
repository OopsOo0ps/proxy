// Command proxy-client 是 Proxy 的本机客户端进程（当前为骨架实现）。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/pkg/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	logLevel := flag.String("log-level", "info", "log level: debug|info|warn|error")
	flag.Parse()

	if *showVersion {
		fmt.Printf("proxy-client %s\n", version.Get())
		return
	}

	info := version.Get()
	logger := logging.New(*logLevel)
	logger.Info("starting proxy-client",
		"version", info.Version,
		"commit", info.Commit,
		"platform", info.Platform,
	)

	// 骨架阶段：尚未监听本地代理端口。这里先演示生产服务的基本形态——
	// 阻塞等待退出信号并优雅收尾；本地代理入口将按 README 路线图逐步合入。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("skeleton build: local proxy entry is not implemented yet; waiting for shutdown signal")
	<-ctx.Done()
	logger.Info("shutdown signal received, exiting")
}
