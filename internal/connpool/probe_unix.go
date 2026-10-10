//go:build unix

package connpool

import (
	"errors"
	"io"
	"net"
	"syscall"
)

// probeTCPSyscall 在原始套接字上做一次非阻塞 recv(MSG_PEEK)：
//   - (nil, true)：套接字当前无数据、无关闭事件，连接健康；
//   - (err, true)：有排队数据（服务端回放的伪装响应等）、对端已关闭
//     （FIN/RST）或探测失败，连接不可复用；
//   - (_, false)：连接不支持非阻塞探测，调用方退回期限读。
//
// MSG_PEEK 不消费数据：探测通过后接收队列保持原样，转发不受影响。
// 全程不设置读期限，因此不存在「期限先到期、忽略已排队数据」的竞态，
// 协程被调度延迟也不会漏检。
func probeTCPSyscall(conn *net.TCPConn) (error, bool) {
	sc, err := conn.SyscallConn()
	if err != nil {
		return nil, false
	}
	var (
		pending  bool
		probeErr error
	)
	if err := sc.Read(func(fd uintptr) bool {
		var buf [1]byte
		for {
			n, _, err := syscall.Recvfrom(int(fd), buf[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
			switch {
			case errors.Is(err, syscall.EINTR):
				continue
			case errors.Is(err, syscall.EAGAIN): // 与 EWOULDBLOCK 同值
				return true
			case err != nil:
				probeErr = err
				return true
			case n == 0:
				probeErr = io.EOF
				return true
			default:
				pending = true
				return true
			}
		}
	}); err != nil {
		return nil, false
	}
	switch {
	case pending:
		return errors.New("connpool: unexpected pending data on idle connection"), true
	case probeErr != nil:
		return probeErr, true
	}
	return nil, true
}
