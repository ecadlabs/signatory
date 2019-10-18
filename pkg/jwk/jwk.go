package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
)

// JWK represents a A JSON Web Key
// see https://tools.ietf.org/html/rfc7517
type JWK struct {
	KeyType                         string   `json:"kty"`
	PublicKeyUse                    string   `json:"use,omitempty"`
	KeyOperations                   []string `json:"key_ops,omitempty"`
	Algorithm                       string   `json:"alg,omitempty"`
	KeyID                           string   `json:"kid,omitempty"`
	X509URL                         string   `json:"x5u,omitempty"`
	X509CertificateThumbprint       string   `json:"x5t,omitempty"`
	X509CertificateSHA256Thumbprint string   `json:"x5t#S256,omitempty"`
	X509CertificateChain            []string `json:"x5c,omitempty"`

	// Parameters for Elliptic Curve Keys
	Curve string `json:"crv,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`

	// Parameters for RSA Keys
	N   string      `json:"n,omitempty"`
	E   string      `json:"e,omitempty"`
	P   string      `json:"p,omitempty"`
	Q   string      `json:"q,omitempty"`
	DP  string      `json:"dp,omitempty"`
	DQ  string      `json:"dq,omitempty"`
	QI  string      `json:"qi,omitempty"`
	Oth []*RSAPrime `json:"oth,omitempty"`

	// Same name, different meaning for EC and RSA
	D string `json:"d,omitempty"`

	// Symmetric
	K string `json:"k,omitempty"`

	// Microsoft extension?
	KeyHSM string `json:"key_hsm,omitempty"`
}

// RSAPrime represents RSA prime
// https://tools.ietf.org/html/rfc7518#section-6.3.2.7
type RSAPrime struct {
	R string `json:"r,omitempty"`
	D string `json:"d,omitempty"`
	T string `json:"t,omitempty"`
}

// ErrPublic is returned if no private part is present in the JWK
var ErrPublic = errors.New("public key")

func parseBase64UInt(s string) (*big.Int, error) {
	buf, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(buf), nil
}

func (j *JWK) ecPublicKey() (k *ecdsa.PublicKey, err error) {
	var key ecdsa.PublicKey
	if key.Curve = cryptoutils.NamedCurve(j.Curve); key.Curve == nil {
		return nil, fmt.Errorf("jwk: unknown curve: %s", j.Curve)
	}
	if key.X, err = parseBase64UInt(j.X); err != nil {
		return nil, err
	}
	if key.Y, err = parseBase64UInt(j.Y); err != nil {
		return nil, err
	}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, fmt.Errorf("jwk: invalid point: %d, %d", key.X, key.Y)
	}

	return &key, nil
}

func (j *JWK) rsaPublicKey() (k *rsa.PublicKey, err error) {
	var key rsa.PublicKey
	if key.N, err = parseBase64UInt(j.N); err != nil {
		return nil, err
	}
	e, err := parseBase64UInt(j.E)
	if err != nil {
		return nil, err
	}
	key.E = int(e.Int64())

	return &key, nil
}

// PublicKey decodes a public key represented in JWK
func (j *JWK) PublicKey() (crypto.PublicKey, error) {
	switch j.KeyType {
	case "EC", "EC-HSM":
		pub, err := j.ecPublicKey()
		if err != nil {
			// Return nil interface instead of (*ecdsa.PublicKey)(nil)!
			return nil, err
		}
		return pub, nil

	case "RSA", "RSA-HSM":
		key, err := j.rsaPublicKey()
		if err != nil {
			return nil, err
		}
		if key.N.Sign() <= 0 || key.E <= 0 {
			return nil, errors.New("jwk: public key contains zero or negative value")
		}
		if key.E > 1<<31-1 {
			return nil, errors.New("jwk: public key contains large public exponent")
		}

		return key, nil
	}

	return nil, fmt.Errorf("jwk: unknown key type: %s", j.KeyType)
}

// PrivateKey decodes a private key represented in JWK
func (j *JWK) PrivateKey() (cryptoutils.PrivateKey, error) {
	switch j.KeyType {
	case "EC", "EC-HSM":
		if j.D == "" {
			return nil, ErrPublic
		}
		pub, err := j.ecPublicKey()
		if err != nil {
			return nil, err
		}
		key := ecdsa.PrivateKey{
			PublicKey: *pub,
		}
		if key.D, err = parseBase64UInt(j.D); err != nil {
			return nil, err
		}

		return &key, nil

	case "RSA", "RSA-HSM":
		if j.D == "" {
			return nil, ErrPublic
		}

		pub, err := j.rsaPublicKey()
		if err != nil {
			return nil, err
		}
		key := rsa.PrivateKey{
			PublicKey: *pub,
		}
		if key.D, err = parseBase64UInt(j.D); err != nil {
			return nil, err
		}
		key.Primes = make([]*big.Int, 2+len(j.Oth))
		if key.Primes[0], err = parseBase64UInt(j.P); err != nil {
			return nil, err
		}
		if key.Primes[1], err = parseBase64UInt(j.Q); err != nil {
			return nil, err
		}

		for i, a := range j.Oth {
			r, err := parseBase64UInt(a.R)
			if err != nil {
				return nil, err
			}
			if r.Sign() <= 0 {
				return nil, errors.New("jwk: private key contains zero or negative prime")
			}
			key.Primes[i+2] = r
		}

		if err = key.Validate(); err != nil {
			return nil, err
		}
		key.Precompute()

		return &key, nil
	}

	return nil, fmt.Errorf("jwk: unknown key type: %s", j.KeyType)
}

func (j *JWK) populateECPublicKey(key *ecdsa.PublicKey) {
	j.KeyType = "EC"
	j.Curve = key.Params().Name
	j.X = base64.RawURLEncoding.EncodeToString(key.X.Bytes())
	j.Y = base64.RawURLEncoding.EncodeToString(key.Y.Bytes())
}

// EncodePrivateKey returns a JWT populated with data from the private key
func EncodePrivateKey(key cryptoutils.PrivateKey) (jwk *JWK, err error) {
	jwk = new(JWK)
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		jwk.populateECPublicKey(&k.PublicKey)
		jwk.D = base64.RawURLEncoding.EncodeToString(k.D.Bytes())

	default:
		return nil, fmt.Errorf("jwk: unknown private key type: %T", key)
	}

	return jwk, nil
}

// EncodePublicKey returns a JWT populated with data from the private key
func EncodePublicKey(key crypto.PublicKey, hsm bool) (jwk *JWK, err error) {
	jwk = new(JWK)
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		jwk.populateECPublicKey(k)

	default:
		return nil, fmt.Errorf("jwk: unknown private key type: %T", key)
	}

	return jwk, nil
}
