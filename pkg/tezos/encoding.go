package tezos

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

// tzPrefix is a comparable type unlike slice
type tzPrefix struct {
	plen int
	mlen int
	p    [5]byte
}

func (t *tzPrefix) prefix() []byte {
	return t.p[:t.plen]
}

// Common prefixes
// See https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/base58.ml
var (
	// 32
	pBlockHash                     = tzPrefix{plen: 2, mlen: 32, p: [5]byte{1, 52}}        // B(51)
	pOperationHash                 = tzPrefix{plen: 2, mlen: 32, p: [5]byte{5, 116}}       // o(51)
	pOperationListHash             = tzPrefix{plen: 2, mlen: 32, p: [5]byte{133, 233}}     // Lo(52)
	pOperationListListHash         = tzPrefix{plen: 3, mlen: 32, p: [5]byte{29, 159, 109}} // LLo(53)
	pProtocolHash                  = tzPrefix{plen: 2, mlen: 32, p: [5]byte{2, 170}}       // P(51)
	pContextHash                   = tzPrefix{plen: 2, mlen: 32, p: [5]byte{79, 199}}      // Co(52)
	pBlockMetadataHash             = tzPrefix{plen: 2, mlen: 32, p: [5]byte{234, 249}}     // bm(52)
	pOperationMetadataHash         = tzPrefix{plen: 2, mlen: 32, p: [5]byte{5, 183}}       // r(51)
	pOperationMetadataListHash     = tzPrefix{plen: 2, mlen: 32, p: [5]byte{134, 39}}      // Lr(52)
	pOperationMetadataListListHash = tzPrefix{plen: 2, mlen: 32, p: [5]byte{29, 159, 182}} // LLr(53)

	// 20
	pED25519PublicKeyHash   = tzPrefix{plen: 3, mlen: 20, p: [5]byte{6, 161, 159}} // tz1(36)
	pSECP256K1PublicKeyHash = tzPrefix{plen: 3, mlen: 20, p: [5]byte{6, 161, 161}} // tz2(36)
	pP256PublicKeyHash      = tzPrefix{plen: 3, mlen: 20, p: [5]byte{6, 161, 164}} // tz3(36)
	pContractHash           = tzPrefix{plen: 3, mlen: 20, p: [5]byte{2, 90, 121}}  // KT1(36)

	// 16
	pCryptoboxPublicKeyHash = tzPrefix{plen: 2, mlen: 16, p: [5]byte{153, 103}} // id(30)

	// 32
	pED25519Seed        = tzPrefix{plen: 4, mlen: 32, p: [5]byte{13, 15, 58, 7}}     // edsk(54)
	pED25519PublicKey   = tzPrefix{plen: 4, mlen: 32, p: [5]byte{13, 15, 37, 217}}   // edpk(54)
	pSECP256K1SecretKey = tzPrefix{plen: 4, mlen: 32, p: [5]byte{17, 162, 224, 201}} // spsk(54)
	pP256SecretKey      = tzPrefix{plen: 4, mlen: 32, p: [5]byte{16, 81, 238, 189}}  // p2sk(54)

	// 56
	pED25519EncryptedSeed        = tzPrefix{plen: 5, mlen: 56, p: [5]byte{7, 90, 60, 179, 41}}    // edesk(88)
	pSECP256K1EncryptedSecretKey = tzPrefix{plen: 5, mlen: 56, p: [5]byte{9, 237, 241, 174, 150}} // spesk(88)
	pP256EncryptedSecretKey      = tzPrefix{plen: 5, mlen: 56, p: [5]byte{9, 48, 57, 115, 171}}   // p2esk(88)

	// 33
	pSECP256K1PublicKey = tzPrefix{plen: 4, mlen: 33, p: [5]byte{3, 254, 226, 86}}  // sppk(55)
	pP256PublicKey      = tzPrefix{plen: 4, mlen: 33, p: [5]byte{3, 178, 139, 127}} // p2pk(55)
	pSECP256K1Scalar    = tzPrefix{plen: 3, mlen: 33, p: [5]byte{38, 248, 136}}     // SSp(53)
	pSECP256K1Element   = tzPrefix{plen: 3, mlen: 33, p: [5]byte{5, 92, 0}}         // GSp(54)

	// 64
	pED25519SecretKey   = tzPrefix{plen: 4, mlen: 64, p: [5]byte{43, 246, 78, 7}}       // edsk(98)
	pED25519Signature   = tzPrefix{plen: 5, mlen: 64, p: [5]byte{9, 245, 205, 134, 18}} // edsig(99)
	pSECP256K1Signature = tzPrefix{plen: 5, mlen: 64, p: [5]byte{13, 115, 101, 19, 63}} // spsig1(99)
	pP256Signature      = tzPrefix{plen: 4, mlen: 64, p: [5]byte{54, 240, 44, 52}}      // p2sig(98)
	pGenericSignature   = tzPrefix{plen: 3, mlen: 64, p: [5]byte{4, 130, 43}}           // sig(96)

	// 4
	pChainID = tzPrefix{plen: 3, mlen: 4, p: [5]byte{87, 82, 0}}

	// 169
	pSaplingSpendingKey = tzPrefix{plen: 4, mlen: 169, p: [5]byte{11, 237, 20, 92}} // sask(241)

	// 43
	pSaplingAddress = tzPrefix{plen: 4, mlen: 43, p: [5]byte{18, 71, 40, 223}} // zet1(69)
)

// Full list of prefixes with payload lengths
var commonPrefixes = []tzPrefix{
	pBlockHash,
	pOperationHash,
	pOperationListHash,
	pOperationListListHash,
	pProtocolHash,
	pContextHash,
	pED25519PublicKeyHash,
	pSECP256K1PublicKeyHash,
	pP256PublicKeyHash,
	pContractHash,
	pCryptoboxPublicKeyHash,
	pED25519Seed,
	pED25519PublicKey,
	pSECP256K1SecretKey,
	pP256SecretKey,
	pED25519EncryptedSeed,
	pSECP256K1EncryptedSecretKey,
	pP256EncryptedSecretKey,
	pSECP256K1PublicKey,
	pP256PublicKey,
	pSECP256K1Scalar,
	pSECP256K1Element,
	pED25519SecretKey,
	pED25519Signature,
	pSECP256K1Signature,
	pP256Signature,
	pGenericSignature,
	pChainID,
}

// ErrPrefix is returned in case of unknown Tezos base58 prefix
var ErrPrefix = errors.New("unknown Tezos base58 prefix")

func decodeBase58(data string) (prefix tzPrefix, payload []byte, err error) {
	buf, err := DecodeBase58Check(data)
	if err != nil {
		return
	}
	for _, p := range commonPrefixes {
		prefix := p.prefix()
		if bytes.HasPrefix(buf, prefix) {
			if len(buf)-len(prefix) != p.mlen {
				return p, nil, fmt.Errorf("tezos: invalid base58 message length: expected %d, got %d", p.mlen, len(buf)-len(prefix))
			}
			return p, buf[len(prefix):], nil
		}
	}
	err = ErrPrefix
	return
}

func encodeBase58(prefix tzPrefix, payload []byte) string {
	p := prefix.prefix()
	data := make([]byte, len(p)+len(payload))
	copy(data, p)
	copy(data[len(p):], payload)
	return EncodeBase58Check(data)
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
