package rpc

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type Client struct {
	conn net.Conn
}

func NewClient(conn net.Conn) *Client {
	return &Client{conn: conn}
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func roundTrip[T any](ctx context.Context, conn net.Conn, req *Request) (*T, error) {
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Time{})
	}

	reqBuf, err := cbor.Marshal(req)
	if err != nil {
		return nil, err
	}

	wrBuf := make([]byte, len(reqBuf)+4)
	binary.BigEndian.PutUint32(wrBuf, uint32(len(reqBuf)))
	copy(wrBuf[4:], reqBuf)
	if _, err := conn.Write(wrBuf); err != nil {
		return nil, err
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	rBuf := make([]byte, int(binary.BigEndian.Uint32(lenBuf[:])))
	if _, err := io.ReadFull(conn, rBuf); err != nil {
		return nil, err
	}
	var res T
	if err := cbor.Unmarshal(rBuf, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *Client) Initialize(ctx context.Context, cred *Credentials) error {
	res, err := roundTrip[SimpleResult](ctx, c.conn, &Request{Initialize: cred})
	if err != nil {
		return err
	}
	return res.Error()
}

func (c *Client) Import(ctx context.Context, keyData []byte) (publicKey *PublicKey, handle uint64, err error) {
	res, err := roundTrip[Result[ImportResult]](ctx, c.conn, &Request{
		Import: keyData,
	})
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, 0, err
	}
	return &res.Ok.PublicKey, res.Ok.Handle, nil
}

func (c *Client) Generate(ctx context.Context, keyType KeyType) (privateKeyData []byte, publicKey *PublicKey, err error) {
	res, err := roundTrip[Result[GenerateResult]](ctx, c.conn, &Request{
		Generate: &keyType,
	})
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, nil, err
	}
	return res.Ok.PrivateKey, &res.Ok.PublicKey, nil
}

func (c *Client) GenerateAndImport(ctx context.Context, keyType KeyType) (privateKeyData []byte, publicKey *PublicKey, handle uint64, err error) {
	res, err := roundTrip[Result[GenerateAndImportResult]](ctx, c.conn, &Request{
		GenerateAndImport: &keyType,
	})
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, nil, 0, err
	}
	return res.Ok.PrivateKey, &res.Ok.PublicKey, res.Ok.Handle, nil
}

func (c *Client) Sign(ctx context.Context, handle uint64, message []byte) (sig *Signature, err error) {
	res, err := roundTrip[Result[Signature]](ctx, c.conn, &Request{
		Sign: &SignRequest{Handle: handle, Msg: message},
	})
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, err
	}
	return res.Ok, nil
}

func (c *Client) SignWith(ctx context.Context, keyData []byte, message []byte) (sig *Signature, err error) {
	res, err := roundTrip[Result[Signature]](ctx, c.conn, &Request{
		SignWith: &SignWithRequest{KeyData: keyData, Msg: message},
	})
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, err
	}
	return res.Ok, nil
}

func (c *Client) PublicKey(ctx context.Context, handle uint64) (publicKey *PublicKey, err error) {
	res, err := roundTrip[Result[PublicKey]](ctx, c.conn, &Request{
		PublicKey: &handle,
	})
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, err
	}
	return res.Ok, nil
}

func (c *Client) PublicKeyFrom(ctx context.Context, data []byte) (publicKey *PublicKey, err error) {
	res, err := roundTrip[Result[PublicKey]](ctx, c.conn, &Request{
		PublicKeyFrom: data,
	})
	if err == nil && res.Error() != nil {
		err = res.Error()
	}
	if err != nil {
		return nil, err
	}
	return res.Ok, nil
}
