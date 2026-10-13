// Package socks5 实现 SOCKS5 入站代理（RFC 1928 / RFC 1929）。
// 地址编码（ATYP + ADDR + PORT）与命令码与 Trojan 共享，定义见 internal/sockswire。
package socks5

import "github.com/OopsOo0ps/proxy/internal/sockswire"

// SOCKS5 常量。
const (
	Version = 0x05

	// 认证方法（RFC 1928 第 3 节）。
	MethodNoAuth       = 0x00
	MethodUserPass     = 0x02
	MethodNoAcceptable = 0xFF

	// 用户名/密码子协商（RFC 1929）。
	UserPassVersion    = 0x01
	UserPassStatusOK   = 0x00
	UserPassStatusFail = 0x01

	// 命令与地址类型：定义见 internal/sockswire；保留别名便于包内与既有测试引用。
	CmdConnect      = sockswire.CmdConnect
	CmdBind         = sockswire.CmdBind
	CmdUDPAssociate = sockswire.CmdUDPAssociate

	ATYPIPv4   = sockswire.ATYPIPv4
	ATYPDomain = sockswire.ATYPDomain
	ATYPIPv6   = sockswire.ATYPIPv6

	// 回复码。
	ReplySuccess         = 0x00
	ReplyGeneralFailure  = 0x01
	ReplyNotAllowed      = 0x02 // connection not allowed by ruleset（路由拒绝）
	ReplyConnRefused     = 0x05
	ReplyCmdNotSupported = 0x07
)
