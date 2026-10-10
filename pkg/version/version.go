// Package version 提供构建期注入的版本信息。
//
// Version、Commit 与 BuildDate 由构建流程通过 -ldflags 注入，
// 未注入时回退为开发占位值。
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version 是构建时注入的版本号。
	Version = "dev"
	// Commit 是构建时注入的提交哈希。
	Commit = "none"
	// BuildDate 是构建时注入的 UTC 时间戳。
	BuildDate = "unknown"
)

// Info 描述一次构建的版本元数据。
type Info struct {
	Version   string
	Commit    string
	BuildDate string
	GoVersion string
	Platform  string
}

// Get 返回当前二进制的版本信息。
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String 返回人类可读的单行版本描述。
func (i Info) String() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s, %s)",
		i.Version, i.Commit, i.BuildDate, i.GoVersion, i.Platform)
}
