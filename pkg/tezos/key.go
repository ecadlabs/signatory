package tezos

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
)

var (
	// ErrPrivateKey is returned when private key type is unknown
	ErrPrivateKey = errors.New("tezos: unknown private key type")
	// ErrPublicKey is returned when private key type is unknown
	ErrPublicKey = errors.New("tezos: unknown public key type")
	// ErrPrivateKeyValue is returned when elliptic D value of unexpected order is provided
	ErrPrivateKeyValue = errors.New("tezos: invalid elliptic curve private key value")
	// ErrPassphrase is returned when required passphrase is not provided
	ErrPassphrase = errors.New("tezos: passphrase required")
	// ErrPrivateKeyDecrypt is returned if attempt to decrypt the private key has been failed
	ErrPrivateKeyDecrypt = errors.New("tezos: unable to decrypt the private key")
)

const (
	encIterations = 32768
	encKeyLen     = 32
)

// see https://golang.org/src/crypto/x509/sec1.go
func ecPrivateKeyFromBytes(b []byte, curve elliptic.Curve) (key *ecdsa.PrivateKey, err error) {
	k := new(big.Int).SetBytes(b)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, ErrPrivateKeyValue
	}

	priv := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: k,
	}

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(b) > len(privateKey) {
		if b[0] != 0 {
			return nil, errors.New("tezos: invalid private key length")
		}
		b = b[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(b):], b)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return &priv, nil
}

// PassphraseFunc is a callback used to obtain a passphrase for decryption of the private key
type PassphraseFunc func() ([]byte, error)

func isEncrypted(prefix tzPrefix) (unencrypted tzPrefix, ok bool) {
	switch prefix {
	case pED25519EncryptedSeed:
		return pED25519Seed, true
	case pSECP256K1EncryptedSecretKey:
		return pSECP256K1SecretKey, true
	case pP256EncryptedSecretKey:
		return pP256SecretKey, true
	}
	return
}

// ParsePrivateKey parses base58 encoded private key
func ParsePrivateKey(data string, passFunc PassphraseFunc) (priv cryptoutils.PrivateKey, err error) {
	prefix, pl, err := decodeBase58(data)
	if err != nil {
		return
	}

	// See https://github.com/murbard/pytezos/blob/master/pytezos/crypto.py#L67
	if unencPrefix, ok := isEncrypted(prefix); ok {
		// Decrypt
		if passFunc == nil {
			return nil, ErrPassphrase
		}
		passphrase, err := passFunc()
		if err != nil {
			return nil, err
		}
		if len(passphrase) == 0 {
			return nil, ErrPassphrase
		}

		salt, box := pl[:8], pl[8:]
		secretboxKey := pbkdf2.Key(passphrase, salt, encIterations, encKeyLen, sha512.New)

		var (
			tmp   [32]byte
			nonce [24]byte
		)
		copy(tmp[:], secretboxKey)
		opened, ok := secretbox.Open(nil, box, &nonce, &tmp)
		if !ok {
			return nil, ErrPrivateKeyDecrypt
		}

		prefix = unencPrefix
		pl = opened
	}

	switch prefix {
	case pSECP256K1SecretKey, pP256SecretKey:
		var curve elliptic.Curve
		if prefix == pSECP256K1SecretKey {
			curve = cryptoutils.S256()
		} else {
			curve = elliptic.P256()
		}
		return ecPrivateKeyFromBytes(pl, curve)

	case pED25519Seed:
		if l := len(pl); l != ed25519.SeedSize {
			return nil, fmt.Errorf("tezos: invalid ED25519 seed length: %d", l)
		}
		return ed25519.NewKeyFromSeed(pl), nil

	case pED25519SecretKey:
		if l := len(pl); l != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("tezos: invalid ED25519 private key length: %d", l)
		}
		return ed25519.PrivateKey(pl), nil
	}

	return nil, ErrPrivateKey
}

// See https://github.com/golang/go/blob/master/src/crypto/elliptic/elliptic.go
func unmarshalCompressed(curve elliptic.Curve, data []byte) (x, y *big.Int, err error) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+byteLen {
		return nil, nil, fmt.Errorf("tezos: (%s) invalid public key length: %d", curve.Params().Name, len(data))
	}
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, nil, fmt.Errorf("tezos: (%s) invalid public key compression", curve.Params().Name)
	}
	p := curve.Params().P
	x = new(big.Int).SetBytes(data[1:])
	if x.Cmp(p) >= 0 {
		return nil, nil, fmt.Errorf("tezos: (%s) invalid public key", curve.Params().Name)
	}

	// secp256k1 polynomial: x³ + b
	// P-* polynomial: x³ - 3x + b
	y = new(big.Int).Mul(x, x)
	y.Mul(y, x)
	if curve != cryptoutils.S256() {
		x1 := new(big.Int).Lsh(x, 1)
		x1.Add(x1, x)
		y.Sub(y, x1)
	}
	y.Add(y, curve.Params().B)
	y.Mod(y, curve.Params().P)
	y.ModSqrt(y, p)

	if y == nil {
		return nil, nil, fmt.Errorf("tezos: (%s) invalid public key", curve.Params().Name)
	}
	if byte(y.Bit(0)) != data[0]&1 {
		y.Neg(y).Mod(y, p)
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil, fmt.Errorf("tezos: (%s) invalid public key", curve.Params().Name)
	}
	return
}

// ParsePublicKey parses base58 encoded public key
func ParsePublicKey(data string) (pub crypto.PublicKey, err error) {
	prefix, pl, err := decodeBase58(data)
	if err != nil {
		return
	}

	switch prefix {
	case pSECP256K1PublicKey, pP256PublicKey:
		var curve elliptic.Curve
		if prefix == pSECP256K1PublicKey {
			curve = cryptoutils.S256()
		} else {
			curve = elliptic.P256()
		}
		x, y, err := unmarshalCompressed(curve, pl)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, nil

	case pED25519PublicKey:
		if l := len(pl); l != ed25519.PublicKeySize {
			return nil, fmt.Errorf("tezos: invalid ED25519 public key length: %d", l)
		}
		return ed25519.PublicKey(pl), nil
	}

	return nil, ErrPublicKey
}

// IsEncryptedPrivateKey returns true if the private key is encrypted
func IsEncryptedPrivateKey(data string) (bool, error) {
	prefix, _, err := decodeBase58(data)
	if err != nil {
		return false, err
	}
	_, ok := isEncrypted(prefix)
	return ok, nil
}

func serializePublicKey(pub crypto.PublicKey) (pubPrefix, hashPrefix tzPrefix, payload []byte, err error) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			hashPrefix = pP256PublicKeyHash
			pubPrefix = pP256PublicKey
		case cryptoutils.S256():
			hashPrefix = pSECP256K1PublicKeyHash
			pubPrefix = pSECP256K1PublicKey
		default:
			err = fmt.Errorf("tezos: unknown curve: %s", key.Params().Name)
			return
		}
		payload = elliptic.MarshalCompressed(key.Curve, key.X, key.Y)
		return

	case ed25519.PublicKey:
		hashPrefix = pED25519PublicKeyHash
		pubPrefix = pED25519PublicKey
		payload = key
		return
	}

	err = fmt.Errorf("tezos: unknown public key type: %T", pub)
	return
}

// EncodePublicKey returns base58 encoded public key
func EncodePublicKey(pub crypto.PublicKey) (res string, err error) {
	prefix, _, payload, err := serializePublicKey(pub)
	if err != nil {
		return "", err
	}

	return encodeBase58(prefix, payload)
}

// EncodePublicKeyHash returns base58 encoded public key hash
func EncodePublicKeyHash(pub crypto.PublicKey) (hash string, err error) {
	_, prefix, payload, err := serializePublicKey(pub)
	if err != nil {
		return "", err
	}

	digest, err := blake2b.New(20, nil)
	if err != nil {
		return "", err
	}
	digest.Write(payload)
	h := digest.Sum(nil)

	return encodeBase58(prefix, h)
}

// GetPublicKeyHash returns BLAKE2B public key hash
func GetPublicKeyHash(pub crypto.PublicKey) (hash []byte, err error) {
	_, _, payload, err := serializePublicKey(pub)
	if err != nil {
		return nil, err
	}

	digest, err := blake2b.New(20, nil)
	if err != nil {
		return nil, err
	}
	digest.Write(payload)
	return digest.Sum(nil), nil
}

// EncodePrivateKey returns base58 encoded private key
func EncodePrivateKey(priv cryptoutils.PrivateKey) (res string, err error) {
	var (
		prefix  tzPrefix
		payload []byte
	)

	switch key := priv.(type) {
	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P256():
			prefix = pP256SecretKey
		case cryptoutils.S256():
			prefix = pSECP256K1SecretKey
		default:
			return "", fmt.Errorf("tezos: unknown curve: %s", key.Params().Name)
		}
		b := key.D.Bytes()
		payload = make([]byte, (key.Params().N.BitLen()+7)>>3)
		copy(payload[len(payload)-len(b):], b)

	case ed25519.PrivateKey:
		prefix = pED25519Seed
		payload = key.Seed()
	}

	return encodeBase58(prefix, payload)
}

// EncodeBinaryPublicKeyHash returns binary representation of the public key hash
func EncodeBinaryPublicKeyHash(s string) (data []byte, err error) {
	prefix, payload, err := decodeBase58(s)
	if err != nil {
		return nil, err
	}

	var tag byte
	switch prefix {
	case pED25519PublicKeyHash:
		tag = tagPublicKeyHashED25519
	case pSECP256K1PublicKeyHash:
		tag = tagPublicKeyHashSECP256K1
	case pP256PublicKeyHash:
		tag = tagPublicKeyP256
	default:
		return nil, errors.New("tezos: unknown public key type")
	}

	data = make([]byte, 1+len(payload))
	data[0] = tag
	copy(data[1:], payload)

	return data, nil
}
