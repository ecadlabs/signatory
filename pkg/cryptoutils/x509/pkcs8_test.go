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

var roundtripTests = []testData{
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

type parseTestData struct {
	name string
	pem  string
}

var parsePrivTests = []parseTestData{
	{
		name: "MLDSA44 Seed",
		pem: `-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMRBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
GhscHR4f
-----END PRIVATE KEY-----`,
	},
	{
		name: "MLDSA44 Expanded",
		pem: `-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----`,
	},
	{
		name: "MLDSA44 Both",
		pem: `-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----`,
	},
}

var parsePubTests = []parseTestData{
	{
		name: "MLDSA44 Public",
		pem: `-----BEGIN PUBLIC KEY-----
MIIFMjALBglghkgBZQMEAxEDggUhANeytHJUquDbReeTDUqY0sl9jxOX0Xidr6Fw
JLMW6b7JT8mUbULxm3mnQTu6oz5xSctC7VEVaTrAQfrLmIretf4OHYYxGEmVtZLD
l9IpTi4U+QqkFLo4JomaxD9MzKy8JumoMrlRGNXLQzy++WYLABOOCBf2HnYsonTD
atVU6yKqwRYuSrAay6HjjE79j4C2WzM9D3LlXf5xzpweu5iJ58VhBsD9c4A6Kuz+
r97XqjyyztpU0SvYzTanjPl1lDtHq9JeiArEUuV0LtHo0agq+oblkMdYwVrk0oQN
kryhpQkPQElll/yn2LlRPxob2m6VCqqY3kZ1B9Sk9aTwWZIWWCw1cvYu2okFqzWB
ZwxKAnd6M+DKcpX9j0/20aCjp2g9ZfX19/xg2gI+gmxfkhRMAvfRuhB1mHVT6pNn
/NdtmQt/qZzUWv24g21D5Fn1GH3wWEeXCaAepoNZNfpwRgmQzT3BukAbqUurHd5B
rGerMxncrKBgSNTE7vJ+4TqcF9BTj0MPLWQtwkFWYN54h32NirxyUjl4wELkKF9D
GYRsRBJiQpdoRMEOVWuiFbWnGeWdDGsqltOYWQcf3MLN51JKe+2uVOhbMY6FTo/i
svPt+slxkSgnCq/R5QRMOk/a/Z/zH5B4S46ORZYUSg2vWGUR09mWK56pWvGXtOX8
YPKx7RXeOlvvX4m9x52RBR2bKBbnT6VFMe/cHL501EiFf0drzVjyHAtlOzt2pOB2
plWaMCcYVVzGP3SFmqurkl8COGHKjND3utsocfZ9VTJtdFETWtRfShumkRj7ssij
DuyTku8/l3Bmya3VxxDMZHsVFNIX2VjHAXw+kP0gwE5nS5BIbpNwoxoAHTL0c5ee
SQZ0nn5Hf6C3RQj4pfI3gxK4PCW9OIygsP/3R4uvQrcWZ+2qyXxGsSlkPlhuWwVa
DCEZRtTzbmdb7Vhg+gQqMV2YJhZNapI3w1pfv0lUkKW9TfJIuVxKrneEtgVnMWas
QkW1tLCCoJ6TI+YvIHjFt2eDRG3v1zatOjcC1JsImESQCmGDM5e8RBmzDXqXoLOH
wZEUdMTUG1PjKpd6y28Op122W7OeWecB52lX3vby1EVZwxp3EitSBOO1whnxaIsU
7QvAuAGz5ugtzUPpwOn0F0TNmBW9G8iCDYuxI/BPrNGxtoXdWisbjbvz7ZM2cPCV
oYC08ZLQixC4+rvfzCskUY4y7qCl4MkEyoRHgAg/OwzS0Li2r2e8NVuUlAJdx7Cn
j6gOOi2/61EyiFHWB4GY6Uk2Ua54fsAlH5Irow6fUd9iptcnhM890gU5MXbfoySl
Er2Ulwo23TSlFKhnkfDrNvAUWwmrZGUbSgMTsplhGiocSIkWJ1mHaKMRQGC6RENI
bfUVIqHOiLMJhcIW+ObtF43VZ7MEoNTK+6iCooNC8XqaomrljbYwCD0sNY/fVmw/
XWKkKFZ7yeqM6VyqDzVHSwv6jzOaJQq0388gg76O77wQVeGP4VNw7ssmBWbYP/Br
IRquxDyim1TM0A+IFaJGXvC0ZRXMfkHzEk8J7/9zkwmrWLKaFFmgC85QOOk4yWeP
cusOTuX9quZtn4Vz/Jf8QrSVn0v4th14Qz6GsDNdbpGRxNi/SHs5BcEIz9asJLDO
t9y3z1H4TQ7Wh7lerrHFM8BvDZcCPZKnCCWDe1m6bLfU5WsKh8IDhiro8xW6WSXo
7e+meTaaIgJ2YVHxapZfn4Hs52zAcLVYaeTbl4TPBcgwsyQsgxI=
-----END PUBLIC KEY-----`,
	},
}

type Pub interface {
	Equal(x crypto.PublicKey) bool
}

type Priv interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

func TestRoundtrip(t *testing.T) {
	for _, test := range roundtripTests {
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

func TestParsePriv(t *testing.T) {
	for _, test := range parsePrivTests {
		t.Run(test.name, func(t *testing.T) {
			privBlock, _ := pem.Decode([]byte(test.pem))
			require.NotNil(t, privBlock)
			priv, err := ParsePKCS8PrivateKey(privBlock.Bytes)
			require.NoError(t, err)

			privBytes, err := MarshalPKCS8PrivateKey(priv)
			require.NoError(t, err)
			priv2, err := ParsePKCS8PrivateKey(privBytes)
			require.NoError(t, err)
			require.True(t, priv2.(Priv).Equal(priv))
		})
	}
}

func TestParsePub(t *testing.T) {
	for _, test := range parsePubTests {
		t.Run(test.name, func(t *testing.T) {
			pubBlock, _ := pem.Decode([]byte(test.pem))
			require.NotNil(t, pubBlock)
			_, err := ParsePKIXPublicKey(pubBlock.Bytes)
			require.NoError(t, err)
		})
	}
}
