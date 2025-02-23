package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/ecadlabs/signatory/pkg/vault/nitro/vsock"
	log "github.com/sirupsen/logrus"
)

type VSockProxy struct {
	Port    uint32
	Address string
}

type Handle interface {
	Shutdown(ctx context.Context) error
}

type handleFunc func(ctx context.Context) error

func (h handleFunc) Shutdown(ctx context.Context) error { return h(ctx) }

func (p *VSockProxy) Start() (handle Handle, err error) {
	if p.Port == 0 {
		return nil, errors.New("missing port number")
	}
	addr, err := net.ResolveTCPAddr("tcp", p.Address)
	if err != nil {
		return nil, err
	}
	log.Infof("Proxying connections to %v...", addr)

	listener, err := vsock.Listen(&vsock.Addr{CID: vsock.ContextAny, Port: p.Port})
	if err != nil {
		return nil, err
	}
	return p.start(listener, addr)
}

func (p *VSockProxy) start(l net.Listener, addr *net.TCPAddr) (handle Handle, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})

	var wg sync.WaitGroup
	hf := func(cc context.Context) error {
		if err := l.Close(); err != nil {
			return err
		}
		select {
		case <-loopDone:
		case <-cc.Done():
			return cc.Err()
		}
		cancel()

		wgDone := make(chan struct{})
		go func() {
			wg.Wait()
			close(wgDone)
		}()

		select {
		case <-wgDone:
			return nil
		case <-cc.Done():
			return cc.Err()
		}
	}

	go func() {
		defer close(loopDone)
		for {
			var conn net.Conn
			conn, err = l.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Error(err)
				}
				return
			}
			log.WithField("from", conn.RemoteAddr()).Debug("Incoming connection")
			wg.Add(1)
			go func() {
				serve(ctx, conn, addr)
				wg.Done()
			}()
		}
	}()

	return handleFunc(hf), nil
}

func serve(ctx context.Context, clientConn net.Conn, addr *net.TCPAddr) {
	remoteConn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		log.Error(err)
		return
	}

	fromClientDone := make(chan struct{})
	fromRemoteDone := make(chan struct{})
	go func() {
		pipe(remoteConn, clientConn)
		close(fromClientDone)
	}()
	go func() {
		pipe(clientConn, remoteConn)
		close(fromRemoteDone)
	}()

	select {
	case <-ctx.Done():
		remoteConn.Close()
		clientConn.Close()

		<-fromClientDone
		<-fromRemoteDone

	case <-fromClientDone:
		<-fromRemoteDone

	case <-fromRemoteDone:
		<-fromClientDone
	}
}

func pipe(dst io.WriteCloser, src io.Reader) {
	_, err := io.Copy(dst, src)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		log.Error(err)
	}
	dst.Close()
}
