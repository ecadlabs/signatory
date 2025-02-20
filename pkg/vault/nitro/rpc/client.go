package rpc

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type Client[C any] struct {
	log  Logger
	conn net.Conn
}

func NewClient[C any](conn net.Conn, log Logger) *Client[C] {
	return &Client[C]{conn: conn, log: log}
}

func (c *Client[C]) Close() error {
	return c.conn.Close()
}

func (c *Client[C]) Conn() net.Conn {
	return c.conn
}

type Logger interface {
	Debugf(format string, args ...interface{})
}

var aLongTimeAgo = time.Unix(1, 0)

func RoundTripRaw[T, C any](ctx context.Context, conn net.Conn, req *Request[C], log Logger) (r T, err error) {
	var res T
	reqBuf, err := cbor.Marshal(req)
	if err != nil {
		return res, err
	}

	intErr := make(chan error)
	done := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			conn.SetDeadline(aLongTimeAgo)
			intErr <- ctx.Err()
		case <-done:
			intErr <- nil
		}
	}()

	defer func() {
		close(done)
		if e := <-intErr; e != nil {
			err = e
		}
		conn.SetDeadline(time.Time{})
	}()

	wrBuf := make([]byte, len(reqBuf)+4)
	binary.BigEndian.PutUint32(wrBuf, uint32(len(reqBuf)))
	copy(wrBuf[4:], reqBuf)
	if log != nil {
		log.Debugf("<<< %s\n", hex.EncodeToString(wrBuf))
	}
	if _, err := conn.Write(wrBuf); err != nil {
		return res, err
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return res, err
	}
	if log != nil {
		log.Debugf(">>> %s\n", hex.EncodeToString(lenBuf[:]))
	}
	rBuf := make([]byte, int(binary.BigEndian.Uint32(lenBuf[:])))
	if _, err := io.ReadFull(conn, rBuf); err != nil {
		return res, err
	}
	if log != nil {
		log.Debugf(">>> %s\n", hex.EncodeToString(rBuf))
	}
	err = cbor.Unmarshal(rBuf, &res)
	return res, err
}

func RoundTrip[T, C any](ctx context.Context, conn net.Conn, req *Request[C], log Logger) (r Result[*T], err error) {
	return RoundTripRaw[Result[*T]](ctx, conn, req, log)
}

func (c *Client[C]) Initialize(ctx context.Context, cred *C) error {
	res, err := RoundTrip[struct{}](ctx, c.conn, &Request[C]{Initialize: cred}, c.log)
	if err != nil {
		return err
	}
	return res.Error()
}

func (c *Client[C]) Import(ctx context.Context, keyData []byte) (publicKey *PublicKey, handle uint64, err error) {
	res, err := RoundTrip[importResult](ctx, c.conn, &Request[C]{
		Import: keyData,
	}, c.log)
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, 0, err
	}
	return &res.Ok.PublicKey, res.Ok.Handle, nil
}

func (c *Client[C]) ImportUnencrypted(ctx context.Context, priv *PrivateKey) (privateKeyData []byte, publicKey *PublicKey, handle uint64, err error) {
	res, err := RoundTrip[generateAndImportResult](ctx, c.conn, &Request[C]{
		ImportUnencrypted: priv,
	}, c.log)
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, nil, 0, err
	}
	return res.Ok.PrivateKey, &res.Ok.PublicKey, res.Ok.Handle, nil
}

func (c *Client[C]) Generate(ctx context.Context, keyType KeyType) (privateKeyData []byte, publicKey *PublicKey, err error) {
	res, err := RoundTrip[generateResult](ctx, c.conn, &Request[C]{
		Generate: &keyType,
	}, c.log)
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, nil, err
	}
	return res.Ok.PrivateKey, &res.Ok.PublicKey, nil
}

func (c *Client[C]) GenerateAndImport(ctx context.Context, keyType KeyType) (privateKeyData []byte, publicKey *PublicKey, handle uint64, err error) {
	res, err := RoundTrip[generateAndImportResult](ctx, c.conn, &Request[C]{
		GenerateAndImport: &keyType,
	}, c.log)
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, nil, 0, err
	}
	return res.Ok.PrivateKey, &res.Ok.PublicKey, res.Ok.Handle, nil
}

func (c *Client[C]) Sign(ctx context.Context, handle uint64, message []byte) (sig *Signature, err error) {
	res, err := RoundTrip[Signature](ctx, c.conn, &Request[C]{
		Sign: &signRequest{Handle: handle, Msg: message},
	}, c.log)
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, err
	}
	return res.Ok, nil
}

func (c *Client[C]) SignWith(ctx context.Context, keyData []byte, message []byte) (sig *Signature, err error) {
	res, err := RoundTrip[Signature](ctx, c.conn, &Request[C]{
		SignWith: &signWithRequest{KeyData: keyData, Msg: message},
	}, c.log)
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, err
	}
	return res.Ok, nil
}

func (c *Client[C]) PublicKey(ctx context.Context, handle uint64) (publicKey *PublicKey, err error) {
	res, err := RoundTrip[PublicKey](ctx, c.conn, &Request[C]{
		PublicKey: &handle,
	}, c.log)
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, err
	}
	return res.Ok, nil
}

func (c *Client[C]) PublicKeyFrom(ctx context.Context, data []byte) (publicKey *PublicKey, err error) {
	res, err := RoundTrip[PublicKey](ctx, c.conn, &Request[C]{
		PublicKeyFrom: data,
	}, c.log)
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, err
	}
	return res.Ok, nil
}
