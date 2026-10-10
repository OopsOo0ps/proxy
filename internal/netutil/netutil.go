// Package netutil 提供跨包共享的网络小工具。
package netutil

import (
	"net"
	"net/netip"
	"strings"
)

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

// SameHostPort 判断两个 host:port 是否指向同一端点（IP 规范化后比较）。
func SameHostPort(a, b string) bool {
	hostA, portA, errA := net.SplitHostPort(a)
	hostB, portB, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil || portA != portB {
		return false
	}
	ipA, errA := netip.ParseAddr(strings.Trim(hostA, "[]"))
	ipB, errB := netip.ParseAddr(strings.Trim(hostB, "[]"))
	if errA == nil && errB == nil {
		return ipA.Compare(ipB) == 0
	}
	return strings.EqualFold(hostA, hostB)
}
