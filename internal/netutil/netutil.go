// Package netutil 提供跨包共享的网络小工具。
package netutil

import "net"

// RemoteIP 从网络地址中提取 IP（不含端口）；解析失败时原样返回。
func RemoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
