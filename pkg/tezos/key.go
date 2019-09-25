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
	ErrPrivateKey = errors.New("unknown private key type")
	// ErrPrivateKeyValue is returned when elliptic D value of unexpected order is provided
	ErrPrivateKeyValue = errors.New("invalid elliptic curve private key value")
	// ErrPassphrase is returned when required passphrase is not provided
	ErrPassphrase = errors.New("passphrase required")
	// ErrPrivateKeyDecrypt is returned if attempt to decrypt the private key has been failed
	ErrPrivateKeyDecrypt = errors.New("unable to decrypt the private key")
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
			return nil, errors.New("invalid private key length")
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
func ParsePrivateKey(data string, passFunc PassphraseFunc) (priv crypto.PrivateKey, err error) {
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
			return nil, fmt.Errorf("invalid ED25519 seed length: %d", l)
		}
		return ed25519.NewKeyFromSeed(pl), nil

	case pED25519SecretKey:
		if l := len(pl); l != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid ED25519 private key length: %d", l)
		}
		return ed25519.PrivateKey(pl), nil
	}

	return nil, ErrPrivateKey
}

// SEC1 compressed point form https://www.secg.org/sec1-v2.pdf
// See https://github.com/decred/dcrd/blob/master/dcrec/secp256k1/pubkey.go#L144
func serializeCoordinates(x, y *big.Int) []byte {
	var format byte = 0x2
	if y.Bit(0) == 1 {
		format |= 0x1
	}

	b := make([]byte, 33)
	b[0] = format
	copy(b[1:], x.Bytes())

	return b
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
			err = fmt.Errorf("unknown curve: %s", key.Params().Name)
			return
		}
		payload = serializeCoordinates(key.X, key.Y)
		return

	case ed25519.PublicKey:
		hashPrefix = pED25519PublicKeyHash
		pubPrefix = pED25519PublicKey
		payload = key
		return
	}

	err = fmt.Errorf("unknown public key type: %T", pub)
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
