package tezos

import (
	"crypto/sha256"

	"github.com/btcsuite/btcutil/base58"
	"github.com/carte7000/crypto/blake2b"
	"github.com/ecadlabs/signatory/crypto"
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

	pS256PubKeyHashPrefix     = "tz3"
	secp256k1PubKeyHashPrefix = "tz2"
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
}

var curveSigMap = map[string]string{
	crypto.CurveP256:  p256SigPrefix,
	crypto.CurveP256K: secp256k1SigPrefix,
}

var curveSigAlgMap = map[string]string{
	crypto.CurveP256:  crypto.SigP256,
	crypto.CurveP256K: crypto.SigP256K,
}

var curvePubKeyPrefixMap = map[string]string{
	crypto.CurveP256:  p256PubKeyPrefix,
	crypto.CurveP256K: secp256k1PubKeyPrefix,
}

var hashCurveMap = map[string]string{
	pS256PubKeyHashPrefix:     crypto.CurveP256,
	secp256k1PubKeyHashPrefix: crypto.CurveP256K,
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

func DecodeKey(prefix []byte, key string) ([]byte, error) {
	decoded, _, err := base58.CheckDecode(key)
	if err != nil {
		return nil, err
	}
	return decoded[len(prefix)-1:], nil
}

func decodeKey(prefix []byte, key string) ([]byte, error) {
	decoded, _, err := base58.CheckDecode(key)
	if err != nil {
		return nil, err
	}
	return decoded[len(prefix)-1:], nil
}

// GetSigAlg return the correct signature algorithm according to the public key hash
func GetSigAlg(pubkeyHash string) string {
	prefix := getPubkeyHashPrefix(pubkeyHash)
	curveName, ok := hashCurveMap[prefix]

	if !ok {
		return ""
	}

	sigAlg, ok := curveSigAlgMap[curveName]

	if !ok {
		return ""
	}

	return sigAlg
}

func getPubkeyHashPrefix(pubkeyHash string) string {
	if len(pubkeyHash) < pubKeyHashPrefixLength {
		return ""
	}

	return pubkeyHash[:pubKeyHashPrefixLength]
}
