package rpc

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/ecadlabs/goblst"
	"github.com/ecadlabs/goblst/minpk"
	"github.com/ecadlabs/gotez/v2/crypt"
	awsutils "github.com/ecadlabs/signatory/pkg/utils/aws"
)

type KeyType string

const (
	KeySecp256k1 KeyType = "Secp256k1"
	KeyNISTP256  KeyType = "NistP256"
	KeyEd25519   KeyType = "Ed25519"
	KeyBLS       KeyType = "Bls"
)

type AWSCredentials struct {
	AccessKeyID     string  `cbor:"access_key_id"`
	SecretAccessKey string  `cbor:"secret_access_key"`
	SessionToken    *string `cbor:"session_token,omitempty"`
	EncryptionKeyID string  `cbor:"encryption_key_id"`
}

func fromEnv(value *string, name string) {
	if *value == "" {
		*value = os.Getenv(name)
	}
}

func LoadAWSCredentials(ctx context.Context, conf awsutils.ConfigProvider) (*AWSCredentials, error) {
	awsConf, err := awsutils.NewAWSConfig(ctx, conf)
	if err != nil {
		return nil, err
	}
	apiCred, err := awsConf.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	rpcCred := AWSCredentials{
		AccessKeyID:     apiCred.AccessKeyID,
		SecretAccessKey: apiCred.SecretAccessKey,
	}
	if apiCred.SessionToken != "" {
		rpcCred.SessionToken = &apiCred.SessionToken
	}
	fromEnv(&rpcCred.EncryptionKeyID, "AWS_KMS_ENCRYPTION_KEY_ID")
	return &rpcCred, nil
}

func (c *AWSCredentials) IsValid() bool {
	return c.AccessKeyID != "" && c.SecretAccessKey != "" && c.EncryptionKeyID != ""
}

type SignRequest struct {
	Handle  uint64 `cbor:"handle"`
	Message []byte `cbor:"message"`
}

type SignWithRequest struct {
	EncryptedPrivateKey []byte `cbor:"encrypted_private_key"`
	Message             []byte `cbor:"message"`
}

type Request[C any] struct {
	Initialize        *C               `cbor:"Initialize,omitempty"`
	Import            []byte           `cbor:"Import,omitempty"`
	ImportUnencrypted *PrivateKey      `cbor:"ImportUnencrypted,omitempty"`
	Generate          *KeyType         `cbor:"Generate,omitempty"`
	GenerateAndImport *KeyType         `cbor:"GenerateAndImport,omitempty"`
	Sign              *SignRequest     `cbor:"Sign,omitempty"`
	SignWith          *SignWithRequest `cbor:"SignWith,omitempty"`
	PublicKey         *uint64          `cbor:"PublicKey,omitempty"`
	PublicKeyFrom     []byte           `cbor:"PublicKeyFrom,omitempty"`
}

type PublicKey struct {
	Secp256k1 []byte `cbor:"Secp256k1,omitempty"`
	P256      []byte `cbor:"NistP256,omitempty"`
	Ed25519   []byte `cbor:"Ed25519,omitempty"`
	BLS       []byte `cbor:"Bls,omitempty"`
}

func (p *PublicKey) PublicKey() (crypt.PublicKey, error) {
	switch {
	case p.Secp256k1 != nil || p.P256 != nil:
		if p.Secp256k1 != nil {
			return crypt.UnmarshalECDSAPublicKey(p.Secp256k1, crypt.S256())
		} else {
			return crypt.UnmarshalECDSAPublicKey(p.P256, elliptic.P256())
		}

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
	Secp256k1 []byte `cbor:"Secp256k1,omitempty"`
	P256      []byte `cbor:"NistP256,omitempty"`
	Ed25519   []byte `cbor:"Ed25519,omitempty"`
	BLS       []byte `cbor:"Bls,omitempty"`
}

func NewPrivateKey(priv crypt.PrivateKey) (*PrivateKey, error) {
	switch priv := priv.(type) {
	case *crypt.ECDSAPrivateKey:
		data := make([]byte, (priv.Params().BitSize+7)/8)
		priv.D.FillBytes(data)
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
	Secp256k1 []byte `cbor:"Secp256k1,omitempty"`
	P256      []byte `cbor:"NistP256,omitempty"`
	Ed25519   []byte `cbor:"Ed25519,omitempty"`
	BLS       []byte `cbor:"Bls,omitempty"`
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
	Source  *RPCError `cbor:"source,omitempty"`
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

type ImportResult struct {
	PublicKey PublicKey `cbor:"public_key"`
	Handle    uint64    `cbor:"handle"`
}

type GenerateResult struct {
	EncryptedPrivateKey []byte    `cbor:"encrypted_private_key"`
	PublicKey           PublicKey `cbor:"public_key"`
}

type GenerateAndImportResult struct {
	EncryptedPrivateKey []byte    `cbor:"encrypted_private_key"`
	PublicKey           PublicKey `cbor:"public_key"`
	Handle              uint64    `cbor:"handle"`
}

type Result[T any] struct {
	Ok  T         `json:",omitempty"`
	Err *RPCError `json:",omitempty"`
}

func (r *Result[T]) Error() error {
	if r.Err != nil {
		return fmt.Errorf("RPC Error: %w", r.Err)
	}
	return nil
}
