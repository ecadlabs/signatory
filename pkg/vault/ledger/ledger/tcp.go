package ledger

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

type TCPTransport struct {
	Addr  string
	Model string
}

func (t *TCPTransport) Enumerate() ([]*DeviceInfo, error) {
	var dev *LedgerDeviceInfo
	if t.Model != "" {
		for _, d := range ledgerDevices {
			if strings.EqualFold(t.Model, d.ID) {
				dev = d
				break
			}
		}
		if dev == nil {
			return nil, fmt.Errorf("ledger: unknown model")
		}
	} else {
		dev = &ledgerNanoS
	}
	return []*DeviceInfo{
		{
			Path:       t.Addr,
			DeviceInfo: dev,
		},
	}, nil
}

func (t *TCPTransport) Open(path string) (Exchanger, error) {
	conn, err := net.Dial("tcp", path)
	if err != nil {
		return nil, fmt.Errorf("tcp: %w", err)
	}
	return &tcpRoundTripper{conn: conn}, nil
}

type tcpRoundTripper struct {
	conn net.Conn
}

func (t *tcpRoundTripper) Exchange(req *APDUCommand) (*APDUResponse, error) {
	data := req.Bytes()
	//log.Printf("> %s", hex.EncodeToString(data))

	buf := make([]byte, len(data)+4)
	binary.BigEndian.PutUint32(buf, uint32(len(data)))
	copy(buf[4:], data)

	if _, err := t.conn.Write(buf); err != nil {
		return nil, fmt.Errorf("tcp: %w", err)
	}

	var ln [4]byte
	if _, err := io.ReadFull(t.conn, ln[:]); err != nil {
		return nil, fmt.Errorf("tcp: %w", err)
	}
	buf = make([]byte, int(binary.BigEndian.Uint32(ln[:])+2))
	if _, err := io.ReadFull(t.conn, buf); err != nil {
		return nil, fmt.Errorf("tcp: %w", err)
	}
	//log.Printf("< %s", hex.EncodeToString(buf))
	res := parseAPDUResponse(buf)
	if res == nil {
		return nil, errors.New("ledger: error parsing APDU response")
	}
	return res, nil
}

func (t *tcpRoundTripper) Close() error { return t.conn.Close() }

var _ Transport = (*TCPTransport)(nil)
