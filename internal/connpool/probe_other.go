//go:build !unix

package connpool

import "net"

// probeTCPSyscall 在非 Unix 平台不提供非阻塞探测，由调用方退回期限读。
func probeTCPSyscall(*net.TCPConn) (error, bool) { return nil, false }
