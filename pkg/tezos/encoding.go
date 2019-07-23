package tezos

import (
	"crypto/sha256"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ecadlabs/crypto/blake2b"
	"github.com/ecadlabs/signatory/pkg/crypto"
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
	crypto.CurveP256:    p256SigPrefix,
	crypto.CurveP256K:   secp256k1SigPrefix,
	crypto.CurveED25519: ed25519SigPrefix,
}

var curvePubKeyPrefixMap = map[string]string{
	crypto.CurveP256:    p256PubKeyPrefix,
	crypto.CurveP256K:   secp256k1PubKeyPrefix,
	crypto.CurveED25519: ed25519PubKeyPrefix,
}

var pubKeyPrefixCurveMap = map[string]string{
	p256PubKeyPrefix:      crypto.CurveP256,
	secp256k1PubKeyPrefix: crypto.CurveP256K,
	ed25519PubKeyPrefix:   crypto.CurveED25519,
}

var hashCurveMap = map[string]string{
	pS256PubKeyHashPrefix:     crypto.CurveP256,
	secp256k1PubKeyHashPrefix: crypto.CurveP256K,
	ed25519PubKeyHashPrefix:   crypto.CurveED25519,
}

var curveHashMap = map[string]string{
	crypto.CurveP256:    pS256PubKeyHashPrefix,
	crypto.CurveP256K:   secp256k1PubKeyHashPrefix,
	crypto.CurveED25519: ed25519PubKeyHashPrefix,
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

func getCurveFromPubkey(pubKey string) string {
	prefix := pubKey[:4]
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

	if curveName == crypto.CurveP256K {
		sig = crypto.CanonizeEncodeP256K(sig)
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
			hash := blake2b.SumX(20, pubKey)
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
