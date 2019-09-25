package tezos

import (
	"testing"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
)

func TestTZKey(t *testing.T) {
	type testCase struct {
		priv string
		pub  string
		hash string
	}

	cases := []testCase{
		// p256 unencrypted
		{
			priv: "p2sk35q9MJHLN1SBHNhKq7oho1vnZL28bYfsSKDUrDn2e4XVcp6ohZ",
			pub:  "p2pk64zMPtYav6yiaHV2DhSQ65gbKMr3gkLQtK7TTQCpJEVUhxxEnxo",
			hash: "tz3VCJEo1rRyyVejmpaRjbgGT9uE66sZmUtQ",
		},
		// ed25519 unencrypted
		{
			priv: "edsk4FTF78Qf1m2rykGpHqostAiq5gYW4YZEoGUSWBTJr2njsDHSnd",
			pub:  "edpkv45regue1bWtuHnCgLU8xWKLwa9qRqv4gimgJKro4LSc3C5VjV",
			hash: "tz1LggX2HUdvJ1tF4Fvv8fjsrzLeW4Jr9t2Q",
		},
		// secp256k1 unencrypted
		{
			priv: "spsk2oTAhiaSywh9ctt8yZLRxL3bo8Mayd3hKFi5iBaoqj2R8bx7ow",
			pub:  "sppk7auhfZa5wAcR8hk3WCw47kHgG3Pp8zaP3ctdAqdDd2dBAeZBof1",
			hash: "tz2VN9n2C56xGLykHCjhNvZQqUeTVisrHjxA",
		},
	}

	as := assert.New(t)

	for i, tst := range cases {
		pk, err := ParsePrivateKey(tst.priv)
		if !as.NoError(err, i) {
			return
		}

		pub := pk.(cryptoutils.PrivateKey).Public()
		hash, err := EncodePublicKeyHash(pub)
		if !as.NoError(err) {
			return
		}

		encPub, err := EncodePublicKey(pub)
		if !as.NoError(err) {
			return
		}

		as.Equal(encPub, tst.pub)
		as.Equal(hash, tst.hash)
	}
}
