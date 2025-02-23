package vsock

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ContextAny        = unix.VMADDR_CID_ANY
	ContextHost       = unix.VMADDR_CID_HOST
	ContextHypervisor = unix.VMADDR_CID_HYPERVISOR

	PortAny = unix.VMADDR_PORT_ANY
)

type Conn struct {
	fd     *os.File
	l_addr Addr
	r_addr Addr
}

var _ net.Conn = (*Conn)(nil)

func wrapErr(err error, op string, source, addr net.Addr) *net.OpError {
	return &net.OpError{
		Op:     op,
		Net:    "vsock",
		Source: source,
		Addr:   addr,
		Err:    err,
	}
}

func (c *Conn) wrapErr(err error, op string) *net.OpError {
	return wrapErr(err, op, &c.l_addr, &c.r_addr)
}

func newUnbound() (*os.File, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	return newFD(fd)
}

func newFD(fd int) (*os.File, error) {
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "vsock"), nil
}

type Addr struct {
	CID  uint32
	Port uint32
}

func (*Addr) Network() string {
	return "vsock"
}

func (a *Addr) String() string {
	return fmt.Sprintf("%d:%d", a.CID, a.Port)
}

func (a *Addr) sockaddr() *unix.SockaddrVM {
	return &unix.SockaddrVM{
		CID:  a.CID,
		Port: a.Port,
	}
}

func newConn(fd *os.File, peer unix.Sockaddr) (*Conn, error) {
	sn, err := unix.Getsockname(int(fd.Fd()))
	if err != nil {
		return nil, err
	}
	l_sa := sn.(*unix.SockaddrVM)
	l_addr := Addr{CID: l_sa.CID, Port: l_sa.Port}

	if peer == nil {
		peer, err = unix.Getpeername(int(fd.Fd()))
		if err != nil {
			return nil, err
		}
	}
	r_sa := peer.(*unix.SockaddrVM)
	r_addr := Addr{CID: r_sa.CID, Port: r_sa.Port}

	return &Conn{fd: fd, l_addr: l_addr, r_addr: r_addr}, nil
}

func newConnFromSys(fd int, peer unix.Sockaddr) (*Conn, error) {
	os_fd, err := newFD(fd)
	if err != nil {
		return nil, err
	}
	return newConn(os_fd, peer)
}

func Dial(addr *Addr) (conn *Conn, err error) {
	fd, err := newUnbound()
	if err != nil {
		return nil, wrapErr(err, "dial", nil, addr)
	}
	defer func() {
		if err != nil {
			fd.Close()
		}
	}()

	switch err := unix.Connect(int(fd.Fd()), addr.sockaddr()); err {
	case unix.EINPROGRESS:
	case nil:
		return newConn(fd, nil)
	default:
		return nil, wrapErr(err, "dial", nil, addr)
	}

	raw, err := fd.SyscallConn()
	if err != nil {
		return nil, err
	}

	var pn unix.Sockaddr
	if poll_err := raw.Write(func(fd uintptr) bool {
		var val int
		val, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
		if err == nil && val != 0 {
			err = unix.Errno(val)
		}
		if err != nil {
			return true
		}
		// check for premature wake up
		pn, err = unix.Getpeername(int(fd))
		return err == nil || err != unix.ENOTCONN
	}); poll_err != nil {
		return nil, wrapErr(poll_err, "dial", nil, addr)
	}
	if err != nil {
		return nil, wrapErr(err, "dial", nil, addr)
	}
	return newConn(fd, pn)
}

func (conn *Conn) Close() error {
	if err := conn.fd.Close(); err != nil {
		return wrapErr(err, "close", nil, nil)
	}
	return nil
}

func (conn *Conn) Read(b []byte) (n int, err error) {
	n, err = conn.fd.Read(b)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, conn.wrapErr(err, "read")
	}
	return n, err
}

func (conn *Conn) Write(b []byte) (n int, err error) {
	n, err = conn.fd.Write(b)
	if err != nil {
		return n, conn.wrapErr(err, "write")
	}
	return n, nil
}

func (conn *Conn) LocalAddr() net.Addr {
	return &conn.l_addr
}

func (conn *Conn) RemoteAddr() net.Addr {
	return &conn.r_addr
}

func (conn *Conn) SetDeadline(t time.Time) error {
	if err := conn.fd.SetDeadline(t); err != nil {
		return wrapErr(err, "set", nil, nil)
	}
	return nil
}

func (conn *Conn) SetReadDeadline(t time.Time) error {
	if err := conn.fd.SetReadDeadline(t); err != nil {
		return wrapErr(err, "set", nil, nil)
	}
	return nil
}

func (conn *Conn) SetWriteDeadline(t time.Time) error {
	if err := conn.fd.SetWriteDeadline(t); err != nil {
		return wrapErr(err, "set", nil, nil)
	}
	return nil
}

type Listener struct {
	fd     *os.File
	raw    syscall.RawConn
	l_addr Addr
}

var _ net.Listener = (*Listener)(nil)

func Listen(addr *Addr) (listener *Listener, err error) {
	fd, err := newUnbound()
	if err != nil {
		return nil, wrapErr(err, "listen", addr, nil)
	}
	defer func() {
		if err != nil {
			fd.Close()
		}
	}()
	if err := unix.Bind(int(fd.Fd()), addr.sockaddr()); err != nil {
		return nil, wrapErr(err, "listen", addr, nil)
	}

	sn, err := unix.Getsockname(int(fd.Fd()))
	if err != nil {
		return nil, wrapErr(err, "listen", addr, nil)
	}
	l_sa := sn.(*unix.SockaddrVM)
	l_addr := Addr{CID: l_sa.CID, Port: l_sa.Port}

	if err := unix.Listen(int(fd.Fd()), unix.SOMAXCONN); err != nil {
		return nil, wrapErr(err, "listen", addr, nil)
	}
	raw, err := fd.SyscallConn()
	if err != nil {
		return nil, err
	}
	return &Listener{fd: fd, raw: raw, l_addr: l_addr}, nil
}

func (l *Listener) Close() error {
	if err := l.fd.Close(); err != nil {
		return wrapErr(err, "close", nil, nil)
	}
	return nil
}

func (l *Listener) AcceptVSock() (conn *Conn, err error) {
	fd, addr, err := unix.Accept(int(l.fd.Fd()))
	switch err {
	case unix.EAGAIN:
	case nil:
		return newConnFromSys(fd, addr)
	default:
		return nil, wrapErr(err, "accept", &l.l_addr, nil)
	}

	if poll_err := l.raw.Read(func(uintptr) bool {
		fd, addr, err = unix.Accept(int(l.fd.Fd()))
		return err == nil || err != unix.EAGAIN
	}); poll_err != nil {
		return nil, wrapErr(poll_err, "accept", &l.l_addr, nil)
	}
	if err != nil {
		return nil, wrapErr(err, "accept", &l.l_addr, nil)
	}

	return newConnFromSys(fd, addr)
}

func (l *Listener) Accept() (conn net.Conn, err error) {
	return l.AcceptVSock()
}

func (l *Listener) Addr() net.Addr {
	return &l.l_addr
}
