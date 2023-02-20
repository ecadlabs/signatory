package tezos

import (
	"encoding/hex"
	"testing"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/stretchr/testify/require"
)

func TestSignVerify(t *testing.T) {
	type testCase struct {
		title string
		priv  string
		pub   string
		pkh   string
		sig   string
	}

	data := "029caecab9e3c579180719b76b585cbdf7e440914b8e09fc0e8c64a26b7a4eacd545ad653100000753c3"
	testCases := []testCase{
		{
			title: "ed25519",
			priv:  "edsk2pVpKe2SZ5v7og52XVCrUmb62WBV6nw1SbJjCD6hSqHtdb3kp1",
			pub:   "edpkvKRFnRbcRakQZWun2CHrbaqug1Ca9GeaTsrQLfjFsdAB98NFMZ",
			pkh:   "tz1M4rtsozgjbrmt1TeRccEMgEnieuthSP4q",
			sig:   "edsigtvJPJ7UGP99yPNcxPuWvXZbp1FCQKWca8331VKFj7Hy66rJXUvWoPhCnkJgAJTGqmHn7R2Xpothdk2bueMDt8EpGYdMMoc",
		},
		{
			title: "secp256k1",
			priv:  "spsk1oxBTLJGHy757hSJ8u5XMCVqxrhaSQaGfE2WGyJrfuvqTT8v43",
			pub:   "sppk7bxf37yvyzfTbRYRfVbBRwU9FbonbrLiSYEW1CniywxkhcTiwTq",
			pkh:   "tz2ShA1oRyrdp6npA1UKL4jikT3JkLWYikzT",
			sig:   "spsig1PQJrWcn4ki2TnDabcThizmEKwaY21gBtCX4kgVw67yogy5nv7RXDm3Z34izgkwWUyF5PZfKWNPghqMtsZWjiT5aSban1F",
		},
		{
			title: "p256",
			priv:  "p2sk3QusZFtXH4jihrFE1UkjDa5VhZvvqGcfXXmtdgjWh3LGt6x1fV",
			pub:   "p2pk65h86CX2XVpXQUpC6BNaxaHngenLkNy9Xy2ykZeK1H9xqzoo5ym",
			pkh:   "tz3a32JzsMp8VyNjXxksWovraeY6uBqbxuCo",
			sig:   "p2sigNjktaHPqD4dKqi7hmp638RkBLgjNQxdUFiRsr1T9VwnmbR8jyjLoX3GkT6cBkia85eE9kEyiRpMYNbexndTWZYGACBzU7",
		},
		{
			title: "bls",
			priv:  "BLsk23i8E6P3JWg9adjHajmpyiP1wuPN3thjEaW1yZDaAHL2ZmPi71",
			pub:   "BLpk1m9JZtn7JjQrZmYQ9ooMF4yVqXAqiYnuHX79S7NAgeX9GhjaFPSqBXbFUjJ2mGch9qkQfFsB",
			pkh:   "tz4MgjDV4dU5v9ptYRiQppjUg8j7fh5vAHfg",
			sig:   "BLsig9dSkWG53YThLpw3oHqcdJAuMqBZiuB9wBhZrJ6gdqQY86C4eVZ7o2ybkwXivWG2iS458c8uvvzkZJd7a9rH7kCjGkRycZKM4ff1oU8cDsDoN15c764PJwqn4Cmp7wgnyKbjsfsXtb",
		},
	}

	for _, c := range testCases {
		t.Run(c.title, func(t *testing.T) {
			priv, err := ParsePrivateKey(c.priv, nil)
			require.NoError(t, err)

			pub, err := EncodePublicKey(priv.Public())
			require.NoError(t, err)
			require.Equal(t, c.pub, pub)

			pkh, err := EncodePublicKeyHash(priv.Public())
			require.NoError(t, err)
			require.Equal(t, c.pkh, pkh)

			msg, _ := hex.DecodeString(data)
			sig, err := cryptoutils.Sign(priv, msg)
			require.NoError(t, err)

			encSig, err := EncodeSignature(sig)
			require.NoError(t, err)
			parsedSig, err := ParseSignature(encSig, nil)
			require.NoError(t, err)

			require.NoError(t, cryptoutils.Verify(priv.Public(), msg, parsedSig))

			refSig, err := ParseSignature(c.sig, nil)
			require.NoError(t, err)
			require.NoError(t, cryptoutils.Verify(priv.Public(), msg, refSig))
		})
	}
}
