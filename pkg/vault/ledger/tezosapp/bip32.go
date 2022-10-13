package tezosapp

import (
	"strconv"
	"strings"
)

// BIP32 represents BIP32 path
type BIP32 []uint32

// BIP32H bit mask is set for so called hardened derivation
const BIP32H = (1 << 31)

// Bytes returns serialized version of the BIP32 derivation path
func (b BIP32) Bytes() []byte {
	data := make([]byte, len(b)*4+1)
	data[0] = uint8(len(b) & 0xff)
	i := 1
	for _, p := range b {
		data[i] = uint8(p >> 24)
		data[i+1] = uint8(p >> 16)
		data[i+2] = uint8(p >> 8)
		data[i+3] = uint8(p)
		i += 4
	}
	return data
}

// BIP32FromBytes parses serialized BIP32 into a binary representation
func BIP32FromBytes(data []byte) BIP32 {
	if len(data) == 0 {
		return nil
	}
	ln := int(data[0])
	i := 1
	res := make(BIP32, ln)
	for ri := range res {
		if i+4 > len(data) {
			return nil
		}
		res[ri] = uint32(data[i])<<24 | uint32(data[i+1])<<16 | uint32(data[i+2])<<8 | uint32(data[i+3])
		i += 4
	}
	return res
}

// String returns string representation of the BIP32 derivation path
func (b BIP32) String() string {
	var res strings.Builder
	for _, p := range b {
		if res.Len() != 0 {
			res.WriteByte('/')
		}
		hardened := false
		if p&BIP32H != 0 {
			p &^= BIP32H
			hardened = true
		}
		res.WriteString(strconv.FormatUint(uint64(p), 10))
		if hardened {
			res.WriteByte('\'')
		}
	}
	return res.String()
}

// ParseBIP32 parses BIP32 string into a binary representation
func ParseBIP32(src string) BIP32 {
	if src == "" {
		return BIP32{}
	}
	parts := strings.Split(src, "/")
	if parts[0] == "m" {
		parts = parts[1:]
	}
	res := make(BIP32, len(parts))
	for i, p := range parts {
		var hardened uint32
		if p[len(p)-1] == '\'' || p[len(p)-1] == 'h' {
			hardened = BIP32H
			p = p[:len(p)-1]
		}
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil
		}
		res[i] = uint32(v) | hardened
	}
	return res
}
