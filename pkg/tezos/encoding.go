package tezos

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
)

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
	// 32
	pBlockHash             = tzPrefix{l: 2, p: [5]byte{1, 52}}        // B(51)
	pOperationHash         = tzPrefix{l: 2, p: [5]byte{5, 116}}       // o(51)
	pOperationListHash     = tzPrefix{l: 2, p: [5]byte{133, 233}}     // Lo(52)
	pOperationListListHash = tzPrefix{l: 3, p: [5]byte{29, 159, 109}} // LLo(53)
	pProtocolHash          = tzPrefix{l: 2, p: [5]byte{2, 170}}       // P(51)
	pContextHash           = tzPrefix{l: 2, p: [5]byte{79, 199}}      // Co(52)

	// 20
	pED25519PublicKeyHash   = tzPrefix{l: 3, p: [5]byte{6, 161, 159}} // tz1(36)
	pSECP256K1PublicKeyHash = tzPrefix{l: 3, p: [5]byte{6, 161, 161}} // tz2(36)
	pP256PublicKeyHash      = tzPrefix{l: 3, p: [5]byte{6, 161, 164}} // tz3(36)
	pContractHash           = tzPrefix{l: 3, p: [5]byte{2, 90, 121}}  // KT1(36)

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
	pSECP256K1Scalar    = tzPrefix{l: 3, p: [5]byte{38, 248, 136}}     // SSp(53)
	pSECP256K1Element   = tzPrefix{l: 3, p: [5]byte{5, 92, 0}}         // GSp(54)

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
	pBlockHash:                   32,
	pOperationHash:               32,
	pOperationListHash:           32,
	pOperationListListHash:       32,
	pProtocolHash:                32,
	pContextHash:                 32,
	pED25519PublicKeyHash:        20,
	pSECP256K1PublicKeyHash:      20,
	pP256PublicKeyHash:           20,
	pContractHash:                20,
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
	pSECP256K1Scalar:             33,
	pSECP256K1Element:            33,
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
				return p, nil, fmt.Errorf("tezos: invalid base58 message length: expected %d, got %d", length, len(buf)-len(prefix))
			}
			return p, buf[len(prefix):], nil
		}
	}

	err = ErrPrefix
	return
}

func encodeBase58(prefix tzPrefix, payload []byte) (string, error) {
	p := prefix.prefix()
	data := make([]byte, len(p)+len(payload))
	copy(data, p)
	copy(data[len(p):], payload)

	return base58.CheckEncode(data, prefix.ver()), nil
}

func DecodeChainID(src string) (res [4]byte, err error) {
	cid, err := hex.DecodeString(src)
	if len(cid) != 4 {
		return res, errors.New("tezos: invalid chain ID")
	}
	if err == nil {
		copy(res[:], cid)
		return
	}

	prefix, cid, err := decodeBase58(src)
	if err != nil {
		return
	}

	if prefix != pChainID {
		return res, errors.New("tezos: invalid chain ID")
	}
	copy(res[:], cid)
	return
}
