package rpc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/ecadlabs/goblst"
	"github.com/ecadlabs/goblst/minpk"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/fxamacker/cbor/v2"
)

type KeyType string

const (
	KeySecp256k1 KeyType = "Secp256k1"
	KeyNISTP256  KeyType = "NistP256"
	KeyEd25519   KeyType = "Ed25519"
	KeyBLS       KeyType = "Bls"
)

type Credentials struct {
	AccessKeyID     string  `cbor:"access_key_id"`
	SecretAccessKey string  `cbor:"secret_access_key"`
	SessionToken    *string `cbor:"session_token,omitempty"`
}

type signRequest struct {
	Handle uint64 `cbor:"handle"`
	Msg    []byte `cbor:"msg"`
}

type signWithRequest struct {
	KeyData []byte `cbor:"key_data"`
	Msg     []byte `cbor:"msg"`
}

type request struct {
	Initialize        *Credentials     `cbor:"Initialize,omitempty"`
	Import            []byte           `cbor:"Import,omitempty"`
	ImportUnencrypted *PrivateKey      `cbor:"ImportUnencrypted"`
	Generate          *KeyType         `cbor:"Generate,omitempty"`
	GenerateAndImport *KeyType         `cbor:"GenerateAndImport,omitempty"`
	Sign              *signRequest     `cbor:"Sign,omitempty"`
	SignWith          *signWithRequest `cbor:"SignWith,omitempty"`
	PublicKey         *uint64          `cbor:"PublicKey,omitempty"`
	PublicKeyFrom     []byte           `cbor:"PublicKeyFrom,omitempty"`
}

type PublicKey struct {
	Secp256k1 []byte `cbor:"Secp256k1"`
	P256      []byte `cbor:"NistP256"`
	Ed25519   []byte `cbor:"Ed25519"`
	BLS       []byte `cbor:"Bls"`
}

func (p *PublicKey) PublicKey() (crypt.PublicKey, error) {
	switch {
	case p.Secp256k1 != nil || p.P256 != nil:
		var data []byte
		if p.Secp256k1 != nil {
			data = p.Secp256k1
		} else {
			data = p.P256
		}
		parsed, err := cryptoutils.ParsePKIXPublicKey(data)
		if err != nil {
			return nil, err
		}
		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("unexpected public key type")
		}
		return (*crypt.ECDSAPublicKey)(pub), nil

	case p.Ed25519 != nil:
		if len(p.Ed25519) != ed25519.PublicKeySize {
			return nil, errors.New("invalid ed25519 public key length")
		}
		return crypt.Ed25519PublicKey(p.Ed25519), nil

	case p.BLS != nil:
		p, err := minpk.PublicKeyFromBytes(p.BLS)
		if err != nil {
			return nil, err
		}
		return (*crypt.BLSPublicKey)(p), nil

	default:
		return nil, errors.New("malformed public key RPC response")
	}
}

type PrivateKey struct {
	Secp256k1 []byte `cbor:"Secp256k1"`
	P256      []byte `cbor:"NistP256"`
	Ed25519   []byte `cbor:"Ed25519"`
	BLS       []byte `cbor:"Bls"`
}

func NewPrivateKey(priv crypt.PrivateKey) (*PrivateKey, error) {
	switch priv := priv.(type) {
	case *crypt.ECDSAPrivateKey:
		data := priv.D.Bytes()
		switch priv.Curve {
		case elliptic.P256():
			return &PrivateKey{P256: data}, nil
		case crypt.S256():
			return &PrivateKey{Secp256k1: data}, nil
		default:
			return nil, fmt.Errorf("unsupported curve %T", priv.Curve)
		}

	case crypt.Ed25519PrivateKey:
		return &PrivateKey{Ed25519: priv}, nil

	case *crypt.BLSPrivateKey:
		return &PrivateKey{BLS: (*goblst.Scalar)(priv).BEBytes()}, nil

	default:
		return nil, fmt.Errorf("unsupported key type %T", priv)
	}
}

type Signature struct {
	Secp256k1 []byte `cbor:"Secp256k1"`
	P256      []byte `cbor:"NistP256"`
	Ed25519   []byte `cbor:"Ed25519"`
	BLS       []byte `cbor:"Bls"`
}

func point(src []byte) (r, s *big.Int) {
	return new(big.Int).SetBytes(src[:32]), new(big.Int).SetBytes(src[32:])
}

const ecdsaSignatureLength = 64

func (s *Signature) Signature() (crypt.Signature, error) {
	switch {
	case s.Secp256k1 != nil:
		if len(s.Secp256k1) != ecdsaSignatureLength {
			return nil, errors.New("invalid Secp256k1 signature length")
		}
		r, s := point(s.Secp256k1)
		return &crypt.ECDSASignature{
			R:     r,
			S:     s,
			Curve: crypt.S256(),
		}, nil

	case s.P256 != nil:
		if len(s.P256) != ecdsaSignatureLength {
			return nil, errors.New("invalid P256 signature length")
		}
		r, s := point(s.P256)
		return &crypt.ECDSASignature{
			R:     r,
			S:     s,
			Curve: elliptic.P256(),
		}, nil

	case s.Ed25519 != nil:
		if len(s.Ed25519) != ed25519.SignatureSize {
			return nil, errors.New("invalid ed25519 signature length")
		}
		return crypt.Ed25519Signature(s.Ed25519[:]), nil

	case s.BLS != nil:
		sig, err := minpk.SignatureFromBytes(s.BLS[:])
		if err != nil {
			return nil, err
		}
		return (*crypt.BLSSignature)(sig), nil

	default:
		return nil, errors.New("malformed signature RPC response")
	}
}

type RPCError struct {
	Message string    `cbor:"message"`
	Source  *RPCError `cbor:"source"`
}

func (e *RPCError) Error() string {
	return e.Message
}

func (e *RPCError) Unwrap() error {
	if e.Source != nil {
		return e.Source
	}
	return nil
}

type importResult struct {
	_         struct{} `cbor:",toarray"`
	PublicKey PublicKey
	Handle    uint64
}

type generateResult struct {
	_          struct{} `cbor:",toarray"`
	PrivateKey []byte
	PublicKey  PublicKey
}

type generateAndImportResult struct {
	_          struct{} `cbor:",toarray"`
	PrivateKey []byte
	PublicKey  PublicKey
	Handle     uint64
}

type result[T any] struct {
	Ok  *T
	Err *RPCError
}

func (r *result[T]) Error() error {
	if r.Err != nil {
		return r.Err
	}
	return nil
}

type simpleResult struct {
	Ok  cbor.SimpleValue
	Err *RPCError
}

func (r *simpleResult) Error() error {
	if r.Err != nil {
		return r.Err
	}
	return nil
}
