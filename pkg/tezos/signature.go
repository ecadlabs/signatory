package tezos

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/ecadlabs/goblst/minpk"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
)

func encodeSignature(sig cryptoutils.Signature) (prefix tzPrefix, payload []byte, err error) {
	switch s := sig.(type) {
	case cryptoutils.ED25519Signature:
		payload = s
		prefix = pED25519Signature
	case *cryptoutils.ECDSASignature:
		sr := s.R.Bytes()
		ss := s.S.Bytes()
		if len(sr) > 32 || len(ss) > 32 {
			return tzPrefix{}, nil, errors.New("tezos: invalid signature size") // unlikely
		}
		payload = make([]byte, 64)
		copy(payload[32-len(sr):], sr)
		copy(payload[64-len(ss):], ss)
		switch s.Curve {
		case elliptic.P256():
			prefix = pP256Signature
		case cryptoutils.S256():
			prefix = pSECP256K1Signature
		default:
			prefix = pGenericSignature
		}
	case *minpk.Signature:
		payload = s.Bytes()
		prefix = pBLS12_381Signature

	default:
		return tzPrefix{}, nil, fmt.Errorf("tezos: unknown signature type %T (%v)", sig, sig)
	}
	return
}

// EncodeGenericSignature returns encoded version of a digital signature in a generic format
func EncodeGenericSignature(sig cryptoutils.Signature) (res string, err error) {
	_, data, err := encodeSignature(sig)
	if err != nil {
		return "", err
	}
	return encodeBase58(pGenericSignature, data), nil
}

// EncodeSignature returns encoded version of a digital signature in a specific format
func EncodeSignature(sig cryptoutils.Signature) (res string, err error) {
	p, data, err := encodeSignature(sig)
	if err != nil {
		return "", err
	}
	return encodeBase58(p, data), nil
}

// ErrSignature is the error returned if the signature type is unknown
var ErrSignature = errors.New("tezos: unknown signature type")

func parseSignature(prefix tzPrefix, data []byte) (sig cryptoutils.Signature, err error) {
	switch prefix {
	case pSECP256K1Signature, pP256Signature:
		var curve elliptic.Curve
		if prefix == pSECP256K1Signature {
			curve = cryptoutils.S256()
		} else {
			curve = elliptic.P256()
		}
		return &cryptoutils.ECDSASignature{
			R:     new(big.Int).SetBytes(data[:32]),
			S:     new(big.Int).SetBytes(data[32:]),
			Curve: curve,
		}, nil

	case pED25519Signature:
		return cryptoutils.ED25519Signature(data), nil

	case pBLS12_381Signature, pGenericAggregateSignature:
		return minpk.SignatureFromBytes(data)

	default:
		return nil, ErrSignature
	}
}

// ParseSignature parses base58 encoded signature. pub is used for generic ("sig...") signatures if not nil
func ParseSignature(s string, pub crypto.PublicKey) (sig cryptoutils.Signature, err error) {
	prefix, pl, err := decodeBase58(s)
	if err != nil {
		return
	}

	if prefix == pGenericSignature {
		switch key := pub.(type) {
		case *ecdsa.PublicKey:
			switch key.Curve {
			case elliptic.P256():
				prefix = pP256Signature
			case cryptoutils.S256():
				prefix = pSECP256K1Signature
			default:
				return nil, fmt.Errorf("tezos: unknown curve: %s", key.Params().Name)
			}

		case ed25519.PublicKey:
			prefix = pED25519Signature

		case *minpk.PublicKey:
			prefix = pBLS12_381Signature

		default:
			return nil, ErrSignature
		}
	}

	return parseSignature(prefix, pl)
}
