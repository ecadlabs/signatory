package utils

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// DigestFunc is an alias for blake2b checksum algorithm
var DigestFunc = blake2b.Sum256

// ErrMsgUnexpectedEnd is returned when message is too short
var ErrMsgUnexpectedEnd = errors.New("unexpected end of message")

func GetByte(buf *[]byte) (b byte, err error) {
	if len(*buf) < 1 {
		return 0, ErrMsgUnexpectedEnd
	}
	b = (*buf)[0]
	*buf = (*buf)[1:]
	return b, nil
}

func GetUint16(buf *[]byte) (i uint16, err error) {
	if len(*buf) < 2 {
		return 0, ErrMsgUnexpectedEnd
	}
	i = binary.BigEndian.Uint16(*buf)
	*buf = (*buf)[2:]
	return i, nil
}

func GetInt16(buf *[]byte) (i int16, err error) {
	ii, err := GetUint16(buf)
	return int16(ii), err
}

func GetUint32(buf *[]byte) (i uint32, err error) {
	if len(*buf) < 4 {
		return 0, ErrMsgUnexpectedEnd
	}
	i = binary.BigEndian.Uint32(*buf)
	*buf = (*buf)[4:]
	return i, nil
}

func GetInt32(buf *[]byte) (i int32, err error) {
	ii, err := GetUint32(buf)
	return int32(ii), err
}

func GetUint64(buf *[]byte) (i uint64, err error) {
	if len(*buf) < 8 {
		return 0, ErrMsgUnexpectedEnd
	}
	i = binary.BigEndian.Uint64(*buf)
	*buf = (*buf)[8:]
	return i, nil
}

func GetInt64(buf *[]byte) (i int64, err error) {
	ii, err := GetUint64(buf)
	return int64(ii), err
}

func GetBytes(buf *[]byte, ln int) (b []byte, err error) {
	if len(*buf) < ln {
		return nil, ErrMsgUnexpectedEnd
	}
	b = (*buf)[:ln]
	*buf = (*buf)[ln:]
	return b, nil
}

func GetBool(buf *[]byte) (b bool, err error) {
	bb, err := GetByte(buf)
	if err != nil {
		return false, err
	}
	switch bb {
	case 0:
		return false, nil
	case 255:
		return true, nil
	}
	return false, fmt.Errorf("invalid boolean value: %d", bb)
}
