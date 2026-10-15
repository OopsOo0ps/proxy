// Command mockpay 是假支付宝网关二进制（迭代②）：宿主 internal/alipaymock
// 的收银台 handler，以证书走 HTTPS——internal/alipay 客户端强制 https 网关
// 地址，假网关必须同介质（本地联调可用 make dev-cert 的自签证书，curl -k
// 或 -cacert 访问）。
//
// 配置全部走命令行旗标：自有最小配置，不进 internal/config 的主 schema
// （设计书 §2.1：外部网关是进程边界，与 proxy-server 走真实回环 HTTP）。
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/OopsOo0ps/proxy/internal/alipaymock"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/version"
)

// shutdownTimeout 是 SIGTERM 后排空在途请求的上限。
const shutdownTimeout = 10 * time.Second

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	listen := flag.String("listen", "127.0.0.1:8443", "HTTPS listen address")
	certPath := flag.String("cert", "var/dev-cert.pem", "TLS certificate PEM (self-signed dev cert: make dev-cert)")
	keyPath := flag.String("key", "var/dev-key.pem", "TLS private key PEM")
	merchantPubPath := flag.String("merchant-pub", "var/alipay-merchant-pub.pem", "merchant RSA2 public key PEM (verify page.pay requests: make dev-keys)")
	gatewayKeyPath := flag.String("gateway-key", "var/alipay-gateway-key.pem", "alipay gateway RSA2 private key PEM (sign async notify: make dev-keys)")
	appID := flag.String("app-id", "2026000000000000", "accepted merchant app_id")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mockpay %s\n", version.Get())
		return
	}

	logger, _ := logging.New("info", "text")

	// 密钥与证书的读取归组装根（cmd）：alipaymock 与 alipay 都保持文件系统无关。
	merchantPub, err := os.ReadFile(*merchantPubPath)
	if err != nil {
		fatal(err)
	}
	gatewayKey, err := os.ReadFile(*gatewayKeyPath)
	if err != nil {
		fatal(err)
	}
	handler, err := alipaymock.New(alipaymock.Options{
		AppID:          *appID,
		MerchantPubPEM: merchantPub,
		NotifyKeyPEM:   gatewayKey,
	})
	if err != nil {
		fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		fatal(err)
	}

	// 先绑定再声明就绪：绑定失败在此暴露，不产生半启动状态。
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fatal(err)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeTLS(ln, "", "") }()
	logger.Info("mockpay listening",
		"addr", ln.Addr().String(),
		"gateway", "https://"+ln.Addr().String()+"/gateway.do",
		"app_id", *appID,
	)

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal(err)
		}
	case <-ctx.Done():
	}

	// SIGTERM/SIGINT：停止 accept 并排空在途请求（确认中的通知投递随之完成）。
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("graceful shutdown incomplete", "error", err)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
	logger.Info("shutdown complete")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "mockpay: %v\n", err)
	os.Exit(1)
}
