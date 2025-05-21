package x509

import (
	"crypto"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

type testData struct {
	name    string
	privKey string
	pubKey  string
}

var tests = []testData{
	{
		name: "Ed25519",
		privKey: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHC6B6yuXgPA87ptaaNeIY2gXzhTd/PJ0XFx1LpAoCgq
-----END PRIVATE KEY-----
`,
		pubKey: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAR353rm+9i9rJfh2eb1/Kta75fpBjQQEKjS8P64GotkM=
-----END PUBLIC KEY-----
`,
	},
	{
		name: "Secp256k1",
		privKey: `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgz5txQN7yJ06M0Afbwgwc
gp52I6vZeFY0GDN38ry+c1ChRANCAAQYzuWHgNL3wk78PYxEnFNYo/q0ryqaZzam
GLhmBjCjGI5tCGHIzvPBg8hVPiVb6qdaQpHjYNJ/yplN7TgajKqa
-----END PRIVATE KEY-----
`,
		pubKey: `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGM7lh4DS98JO/D2MRJxTWKP6tK8qmmc2
phi4ZgYwoxiObQhhyM7zwYPIVT4lW+qnWkKR42DSf8qZTe04Goyqmg==
-----END PUBLIC KEY-----
`,
	},
	{
		name: "P256",
		privKey: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfw45sec0YpLr/cqI
BNpGl7R1CBU+KKbHUcpiB/1E0j2hRANCAATiu/1cmWqvYwnAkcg14Kr0B0F9OZg4
I5aFDX31AM2J3PxDay2mbatiCC5U0ktSzc+M99qifTH0A67OFoMc0rzN
-----END PRIVATE KEY-----
`,
		pubKey: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4rv9XJlqr2MJwJHINeCq9AdBfTmY
OCOWhQ199QDNidz8Q2stpm2rYgguVNJLUs3PjPfaon0x9AOuzhaDHNK8zQ==
-----END PUBLIC KEY-----
`,
	},
}

type Pub interface {
	Equal(x crypto.PublicKey) bool
}

type Priv interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

func TestParse(t *testing.T) {
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			privBlock, _ := pem.Decode([]byte(test.privKey))
			require.NotNil(t, privBlock)
			priv, err := ParsePKCS8PrivateKey(privBlock.Bytes)
			require.NoError(t, err)

			pubBlock, _ := pem.Decode([]byte(test.pubKey))
			require.NotNil(t, pubBlock)
			pub, err := ParsePKIXPublicKey(pubBlock.Bytes)
			require.NoError(t, err)

			pub2 := priv.(crypto.Signer).Public()
			require.True(t, pub.(Pub).Equal(pub2))

			privBytes, err := MarshalPKCS8PrivateKey(priv)
			require.NoError(t, err)
			priv2, err := ParsePKCS8PrivateKey(privBytes)
			require.NoError(t, err)

			require.True(t, priv2.(Priv).Equal(priv))
		})
	}
}
