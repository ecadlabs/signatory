package tezos

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
)

/*
import (
	"crypto/sha256"

	"github.com/btcsuite/btcutil/base58"
	eblake2b "github.com/ecadlabs/crypto/blake2b"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"golang.org/x/crypto/blake2b"
)

// DigestFunc is an alias for blake2b checksum algorithm
var DigestFunc = blake2b.Sum256

const (
	pubKeyPrefixLength     = 4
	secretKeyPrefixLength  = 4
	pubKeyHashPrefixLength = 3
)

const (
	p256PubKeyPrefix    = "p2pk"
	p256SecretKeyPrefix = "p2sk"
	p256SigPrefix       = "p2sig"

	secp256k1SigPrefix       = "spsig1"
	secp256k1SecretKeyPrefix = "spsk"
	secp256k1PubKeyPrefix    = "sppk"

	ed25519PubKeyPrefix    = "edpk"
	ed25519SigPrefix       = "edsig"
	ed25519SecretKeyPrefix = "edsk"

	pS256PubKeyHashPrefix     = "tz3"
	secp256k1PubKeyHashPrefix = "tz2"
	ed25519PubKeyHashPrefix   = "tz1"
)

var (
	chainIDPrefix = []byte{0x57, 0x52, 0x00}
)

var prefixMap = map[string][]byte{
	p256PubKeyPrefix:      []byte{3, 178, 139, 127},       // p2pk
	p256SecretKeyPrefix:   []byte{0x10, 0x51, 0xee, 0xbd}, // p2sk
	p256SigPrefix:         []byte{54, 240, 44, 52},        // p2sig
	pS256PubKeyHashPrefix: []byte{0x06, 0xa1, 0xa4},       // tz3

	secp256k1PubKeyPrefix:     []byte{0x03, 0xfe, 0xe2, 0x56},       // sppk
	secp256k1SecretKeyPrefix:  []byte{0x11, 0xa2, 0xe0, 0xc9},       // spsk
	secp256k1SigPrefix:        []byte{0x0d, 0x73, 0x65, 0x13, 0x3f}, // spsig1
	secp256k1PubKeyHashPrefix: []byte{0x06, 0xa1, 0xa1},             // tz2

	ed25519PubKeyPrefix:     []byte{0x0d, 0x0f, 0x25, 0xd9},       // edpk
	ed25519SecretKeyPrefix:  []byte{0x0d, 0x0f, 0x3a, 0x07},       // edsk
	ed25519SigPrefix:        []byte{0x09, 0xf5, 0xcd, 0x86, 0x12}, // edsig
	ed25519PubKeyHashPrefix: []byte{0x06, 0xa1, 0x9f},             // tz1
}

var curveSigMap = map[string]string{
	cryptoutils.CurveP256:    p256SigPrefix,
	cryptoutils.CurveP256K:   secp256k1SigPrefix,
	cryptoutils.CurveED25519: ed25519SigPrefix,
}

var curvePubKeyPrefixMap = map[string]string{
	cryptoutils.CurveP256:    p256PubKeyPrefix,
	cryptoutils.CurveP256K:   secp256k1PubKeyPrefix,
	cryptoutils.CurveED25519: ed25519PubKeyPrefix,
}

var hashCurveMap = map[string]string{
	pS256PubKeyHashPrefix:     cryptoutils.CurveP256,
	secp256k1PubKeyHashPrefix: cryptoutils.CurveP256K,
	ed25519PubKeyHashPrefix:   cryptoutils.CurveED25519,
}

var curveHashMap = map[string]string{
	cryptoutils.CurveP256:    pS256PubKeyHashPrefix,
	cryptoutils.CurveP256K:   secp256k1PubKeyHashPrefix,
	cryptoutils.CurveED25519: ed25519PubKeyHashPrefix,
}

func base58CheckEncodePrefix(prefix []byte, msg []byte) string {
	sig := []byte{}
	// Append prefix
	sig = append(sig, prefix...)
	sig = append(sig, msg...)
	// Compute checksum
	f := sha256.Sum256(sig)
	f2 := sha256.Sum256(f[:])
	// Append checksum to signature
	sig = append(sig, f2[:4]...)
	return base58.Encode(sig)
}

func getCurveFromPubkeyHash(pubKeyHash string) string {
	prefix := getPubkeyHashPrefix(pubKeyHash)
	curveName, ok := hashCurveMap[prefix]

	if !ok {
		return ""
	}

	return curveName
}

// EncodeSig encode a signature according to the tezos format
func EncodeSig(pubKeyHash string, sig []byte) string {
	curveName := getCurveFromPubkeyHash(pubKeyHash)
	sigPrefix, ok := curveSigMap[curveName]

	if !ok {
		return ""
	}

	if curveName == cryptoutils.CurveP256K {
		sig = cryptoutils.CanonizeEncodeP256K(sig)
	}

	return base58CheckEncodePrefix(prefixMap[sigPrefix], sig)
}

// EncodePubKey encode a public key according to the tezos format
func EncodePubKey(pubKeyHash string, pubKey []byte) string {
	curveName := getCurveFromPubkeyHash(pubKeyHash)

	pubKeyPrefix, ok := curvePubKeyPrefixMap[curveName]

	if !ok {
		return ""
	}

	return base58CheckEncodePrefix(prefixMap[pubKeyPrefix], pubKey)
}

// EncodePubKeyHash encode a pubkey to a Tezos public key hash base on a curve
func EncodePubKeyHash(pubKey []byte, curve string) string {
	if val, ok := curveHashMap[curve]; ok {
		if prefix := prefixMap[val]; ok {
			hash := eblake2b.SumX(20, pubKey)
			return base58CheckEncodePrefix(prefix, hash[:20])
		}
	}
	return ""
}

func decodeKey(prefix []byte, key string) ([]byte, error) {
	decoded, _, err := base58.CheckDecode(key)
	if err != nil {
		return nil, err
	}
	return decoded[len(prefix)-1:], nil
}

func getPubkeyHashPrefix(pubkeyHash string) string {
	if len(pubkeyHash) < pubKeyHashPrefixLength {
		return ""
	}

	return pubkeyHash[:pubKeyHashPrefixLength]
}

*/

// tzPrefix is a comparable type unlike slice
type tzPrefix struct {
	l int
	p [5]byte
}

func (t *tzPrefix) prefix() []byte {
	return t.p[1:t.l]
}

func (t *tzPrefix) ver() byte {
	return t.p[0]
}

// Common prefixes
// See https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/base58.ml
var (
	// 20
	pED25519PublicKeyHash   = tzPrefix{l: 3, p: [5]byte{6, 161, 159}} //  tz1(36)
	pSECP256K1PublicKeyHash = tzPrefix{l: 3, p: [5]byte{6, 161, 161}} // tz2(36)
	pP256PublicKeyHash      = tzPrefix{l: 3, p: [5]byte{6, 161, 164}} // tz3(36)

	// 16
	pCryptoboxPublicKeyHash = tzPrefix{l: 2, p: [5]byte{153, 103}} // id(30)

	// 32
	pED25519Seed        = tzPrefix{l: 4, p: [5]byte{13, 15, 58, 7}}     // edsk(54)
	pED25519PublicKey   = tzPrefix{l: 4, p: [5]byte{13, 15, 37, 217}}   // edpk(54)
	pSECP256K1SecretKey = tzPrefix{l: 4, p: [5]byte{17, 162, 224, 201}} // spsk(54)
	pP256SecretKey      = tzPrefix{l: 4, p: [5]byte{16, 81, 238, 189}}  // p2sk(54)

	// 56
	pED25519EncryptedSeed        = tzPrefix{l: 5, p: [5]byte{7, 90, 60, 179, 41}}    // edesk(88)
	pSECP256K1EncryptedSecretKey = tzPrefix{l: 5, p: [5]byte{9, 237, 241, 174, 150}} // spesk(88)
	pP256EncryptedSecretKey      = tzPrefix{l: 5, p: [5]byte{9, 48, 57, 115, 171}}   // p2esk(88)

	// 33
	pSECP256K1PublicKey = tzPrefix{l: 4, p: [5]byte{3, 254, 226, 86}}  // sppk(55)
	pP256PublicKey      = tzPrefix{l: 4, p: [5]byte{3, 178, 139, 127}} // p2pk(55)

	// 64
	pED25519SecretKey   = tzPrefix{l: 4, p: [5]byte{43, 246, 78, 7}}       // edsk(98)
	pED25519Signature   = tzPrefix{l: 5, p: [5]byte{9, 245, 205, 134, 18}} // edsig(99)
	pSECP256K1Signature = tzPrefix{l: 5, p: [5]byte{13, 115, 101, 19, 63}} // spsig1(99)
	pP256Signature      = tzPrefix{l: 4, p: [5]byte{54, 240, 44, 52}}      // p2sig(98)
	pGenericSignature   = tzPrefix{l: 3, p: [5]byte{4, 130, 43}}           // sig(96)

	// 4
	pChainID = tzPrefix{l: 3, p: [5]byte{87, 82, 0}}
)

// Full list of prefixes with payload lengths
var commonPrefixes = map[tzPrefix]int{
	pED25519PublicKeyHash:        20,
	pSECP256K1PublicKeyHash:      20,
	pP256PublicKeyHash:           20,
	pCryptoboxPublicKeyHash:      16,
	pED25519Seed:                 32,
	pED25519PublicKey:            32,
	pSECP256K1SecretKey:          32,
	pP256SecretKey:               32,
	pED25519EncryptedSeed:        56,
	pSECP256K1EncryptedSecretKey: 56,
	pP256EncryptedSecretKey:      56,
	pSECP256K1PublicKey:          33,
	pP256PublicKey:               33,
	pED25519SecretKey:            64,
	pED25519Signature:            64,
	pSECP256K1Signature:          64,
	pP256Signature:               64,
	pGenericSignature:            64,
	pChainID:                     4,
}

// ErrPrefix is returned in case of unknown Tezos base58 prefix
var ErrPrefix = errors.New("unknown Tezos base58 prefix")

func decodeBase58(data string) (prefix tzPrefix, payload []byte, err error) {
	buf, ver, err := base58.CheckDecode(data)
	if err != nil {
		return
	}

	for p, length := range commonPrefixes {
		prefix := p.prefix()
		if ver == p.ver() && bytes.HasPrefix(buf, prefix) {
			if len(buf)-len(prefix) != length {
				return p, nil, fmt.Errorf("invalid base58 message length: expected %d, got %d", length, len(buf)-len(prefix))
			}
			return p, buf[len(prefix):], nil
		}
	}

	return tzPrefix{}, nil, ErrPrefix
}

func encodeBase58(prefix tzPrefix, payload []byte) (string, error) {
	p := prefix.prefix()
	data := make([]byte, len(p)+len(payload))
	copy(data, p)
	copy(data[len(p):], payload)

	return base58.CheckEncode(data, prefix.ver()), nil
}
