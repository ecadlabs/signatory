package tezos

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

const alphabetStart = 49

var base58alphabetF = []int8{
	0, 1, 2, 3, 4, 5, 6,
	7, 8, -1, -1, -1, -1, -1, -1,
	-1, 9, 10, 11, 12, 13, 14, 15,
	16, -1, 17, 18, 19, 20, 21, -1,
	22, 23, 24, 25, 26, 27, 28, 29,
	30, 31, 32, -1, -1, -1, -1, -1,
	-1, 33, 34, 35, 36, 37, 38, 39,
	40, 41, 42, 43, -1, 44, 45, 46,
	47, 48, 49, 50, 51, 52, 53, 54,
	55, 56, 57,
}

var base58alphabetB = []int8{
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 16, 17, 18, 19, 20, 21, 22,
	23, 25, 26, 27, 28, 29, 31, 32,
	33, 34, 35, 36, 37, 38, 39, 40,
	41, 48, 49, 50, 51, 52, 53, 54,
	55, 56, 57, 58, 60, 61, 62, 63,
	64, 65, 66, 67, 68, 69, 70, 71,
	72, 73,
}

func DecodeBase58(text string) ([]byte, error) {
	i := 0
	// count and skip leading zeros
	for ; i < len(text); i++ {
		c := int(text[i]) - alphabetStart
		if c >= len(base58alphabetF) || base58alphabetF[c] == -1 {
			return nil, fmt.Errorf("base58 decoding error: unexpected character at position %d: %c", i, text[i])
		}
		if base58alphabetF[c] != 0 {
			break
		}
	}
	zeros := i
	acc := make([]byte, 0, len(text)/4)
	for ; i < len(text); i++ {
		c := int(text[i]) - alphabetStart
		if c >= len(base58alphabetF) || base58alphabetF[c] == -1 {
			return nil, fmt.Errorf("base58 decoding error: unexpected character at position %d: %c", i, text[i])
		}
		carry := int(base58alphabetF[c])
		// for every symbol x
		// acc = acc * 58 + x
		// where acc is a little endian arbitrary length integer
		for ii := 0; carry != 0 || ii < len(acc); ii++ {
			var a int
			if ii < len(acc) {
				a = int(acc[ii])
			}
			m := a*58 + carry
			b := m % 256
			carry = m / 256
			if ii < len(acc) {
				acc[ii] = byte(b)
			} else {
				acc = append(acc, byte(b))
			}
		}
	}
	out := make([]byte, len(acc)+zeros)
	for i := 0; i < len(acc); i++ {
		out[i+zeros] = acc[len(acc)-i-1]
	}
	return out, nil
}

func EncodeBase58(data []byte) string {
	i := 0
	// count and skip leading zeros
	for ; i < len(data) && data[i] == 0; i++ {
	}
	zeros := i
	acc := make([]byte, 0, len(data)*5)
	for ; i < len(data); i++ {
		carry := int(data[i])
		for ii := 0; carry != 0 || ii < len(acc); ii++ {
			var a int
			if ii < len(acc) {
				a = int(acc[ii])
			}
			m := a*256 + carry
			b := m % 58
			carry = m / 58
			if ii < len(acc) {
				acc[ii] = byte(b)
			} else {
				acc = append(acc, byte(b))
			}
		}
	}
	out := make([]byte, len(acc)+zeros)
	for i := 0; i < zeros; i++ {
		out[i] = alphabetStart
	}
	for i := 0; i < len(acc); i++ {
		out[i+zeros] = byte(base58alphabetB[acc[len(acc)-i-1]] + alphabetStart)
	}
	return string(out)
}

func DecodeBase58Check(text string) ([]byte, error) {
	buf, err := DecodeBase58(text)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, fmt.Errorf("base58Check decoding error: data is too short: %d", len(buf))
	}
	data := buf[:len(buf)-4]
	sum := buf[len(buf)-4:]
	s0 := sha256.Sum256(data)
	s1 := sha256.Sum256(s0[:])
	if !bytes.Equal(sum, s1[:4]) {
		return nil, errors.New("base58Check decoding error: invalid checksum")
	}
	return data, nil
}

func EncodeBase58Check(data []byte) string {
	s0 := sha256.Sum256(data)
	s1 := sha256.Sum256(s0[:])
	return EncodeBase58(append(data, s1[:4]...))
}
