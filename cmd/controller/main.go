// Command proxy-controller 是 Proxy 的配置管理 CLI（当前为骨架实现）。
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/OopsOo0ps/proxy/pkg/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		_, _ = fmt.Fprintf(out, "proxy-controller: configuration management CLI (skeleton)\n\n")
		_, _ = fmt.Fprintf(out, "Usage:\n  proxy-controller [flags]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("proxy-controller %s\n", version.Get())
		return
	}

	// 骨架阶段：配置读取与下发命令尚未实现。
	fmt.Fprintln(os.Stderr, "proxy-controller skeleton: configuration commands are not implemented yet")
	flag.Usage()
	os.Exit(2)
}
