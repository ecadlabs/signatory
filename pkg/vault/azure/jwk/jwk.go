package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/ecadlabs/gotez/v2/crypt"
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
	Dp  string      `json:"dp,omitempty"`
	Dq  string      `json:"dq,omitempty"`
	Qi  string      `json:"qi,omitempty"`
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

var b64 = base64.RawURLEncoding

func parseBase64UInt(s string) (*big.Int, error) {
	buf, err := b64.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(buf), nil
}

func (j *JWK) ecPublicKey() (k *ecdsa.PublicKey, err error) {
	var key ecdsa.PublicKey
	if key.Curve = curveByName(j.Curve); key.Curve == nil {
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
func (j *JWK) PrivateKey() (crypto.PrivateKey, error) {
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
	j.Curve = curveName(key.Curve)
	j.X = b64.EncodeToString(key.X.Bytes())
	j.Y = b64.EncodeToString(key.Y.Bytes())
}

func (j *JWK) populateRSAPublicKey(key *rsa.PublicKey) {
	j.KeyType = "RSA"
	j.N = b64.EncodeToString(key.N.Bytes())
	j.E = b64.EncodeToString(big.NewInt(int64(key.E)).Bytes())
}

// EncodePrivateKey returns a JWT populated with data from the private key
func EncodePrivateKey(key crypto.PrivateKey) (jwk *JWK, err error) {
	jwk = new(JWK)
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		jwk.populateECPublicKey(&k.PublicKey)
		jwk.D = b64.EncodeToString(k.D.Bytes())

	case *rsa.PrivateKey:
		jwk.populateRSAPublicKey(&k.PublicKey)
		jwk.D = b64.EncodeToString(k.D.Bytes())
		if len(k.Primes) < 2 || len(k.Precomputed.CRTValues) != len(k.Primes)-2 {
			return nil, errors.New("jwk: invalid RSA primes number")
		}
		jwk.P = b64.EncodeToString(k.Primes[0].Bytes())
		jwk.Q = b64.EncodeToString(k.Primes[1].Bytes())
		jwk.Dp = b64.EncodeToString(k.Precomputed.Dp.Bytes())
		jwk.Dq = b64.EncodeToString(k.Precomputed.Dq.Bytes())
		jwk.Qi = b64.EncodeToString(k.Precomputed.Qinv.Bytes())

		if len(k.Primes) > 2 {
			jwk.Oth = make([]*RSAPrime, len(k.Primes)-2)
			for i := 0; i < len(k.Primes)-2; i++ {
				jwk.Oth[i] = &RSAPrime{
					R: b64.EncodeToString(k.Primes[i+2].Bytes()),
					D: b64.EncodeToString(k.Precomputed.CRTValues[i].Exp.Bytes()),
					T: b64.EncodeToString(k.Precomputed.CRTValues[i].Coeff.Bytes()),
				}
			}
		}

	default:
		return nil, fmt.Errorf("jwk: unknown private key type: %T", key)
	}

	return jwk, nil
}

// EncodePublicKey returns a JWT populated with data from the private key
func EncodePublicKey(key crypto.PublicKey) (jwk *JWK, err error) {
	jwk = new(JWK)
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		jwk.populateECPublicKey(k)

	case *rsa.PublicKey:
		jwk.populateRSAPublicKey(k)

	default:
		return nil, fmt.Errorf("jwk: unknown private key type: %T", key)
	}

	return jwk, nil
}

// curveByName returns curve by its standard name or nil
func curveByName(name string) elliptic.Curve {
	switch name {
	case "P-224":
		return elliptic.P224()
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	case "P-256K", "SECP256K1", "secp256k1":
		return crypt.S256()
	default:
		return nil
	}
}

func curveName(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P224():
		return "P-224"
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	case crypt.S256():
		return "P-256K" // https://github.com/Azure/azure-sdk-for-go/blob/main/sdk/security/keyvault/azkeys/constants.go
	default:
		return ""
	}
}
