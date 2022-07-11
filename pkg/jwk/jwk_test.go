//go:build !integration

package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bigInt(s string, base int) *big.Int {
	v, _ := new(big.Int).SetString(s, base)
	return v
}

func parsePrivateKey(buf []byte) (pk interface{}, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	return x509.ParsePKCS8PrivateKey(block.Bytes) // Unencrypted PKCS#8 only
}

func parsePublicKey(buf []byte) (pk interface{}, err error) {
	block, _ := pem.Decode(buf)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	return cryptoutils.ParsePKIXPublicKey(block.Bytes)
}

func TestParse(t *testing.T) {
	type testCase struct {
		jsonData      string
		expectPub     interface{}
		expectPubPem  string
		expectPubErr  error
		expectPriv    interface{}
		expectPrivPem string
		expectPrivErr error
	}

	cases := []testCase{
		{
			jsonData: `{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}`,
			expectPriv: &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     bigInt("21994169848703329112137818087919262246467304847122821377551355163096090930238", 10),
					Y:     bigInt("101451294974385619524093058399734017814808930032421185206609461750712400090915", 10),
				},
				D: bigInt("110246039328358150430804407946042381407500908316371398015658902487828646033409", 10),
			},
			expectPub: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     bigInt("21994169848703329112137818087919262246467304847122821377551355163096090930238", 10),
				Y:     bigInt("101451294974385619524093058399734017814808930032421185206609461750712400090915", 10),
			},
		},
		{
			jsonData:      `{"kty":"EC","crv":"P-256K","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}`,
			expectPrivErr: errors.New("jwk: invalid point: 21994169848703329112137818087919262246467304847122821377551355163096090930238, 101451294974385619524093058399734017814808930032421185206609461750712400090915"),
			expectPubErr:  errors.New("jwk: invalid point: 21994169848703329112137818087919262246467304847122821377551355163096090930238, 101451294974385619524093058399734017814808930032421185206609461750712400090915"),
		},
		{
			jsonData:      `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`,
			expectPrivErr: ErrPublic,
			expectPub: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     bigInt("57807358241436249728379122087876380298924820027722995515715270765240753673285", 10),
				Y:     bigInt("90436541859143682268950424386863654389577770182238183823381687388274600502701", 10),
			},
		},
		{
			jsonData:      `{"kty":"RSA","n":"sux5uN1IxBJcJzkKvw-whhZ6nilpQPdRPikVZHvysoTpO5qXlqfXWiZNX_Jbt-7wN0QvxROfiE1VYg05bXV-6FWFkUug7bPwCno3YfxzfsHauPkzm0Agst6IrORClcRKAeACdsUJQJoNEa2Bo1K2G8BRAAFDB-hV4ru7njM4Qs4iJMWyL80aNZrOkHXnYGn9n0bXTTRuxkJ4xwoLML126beTig2dn8iCxBXZdmNbzMhHun_sDi8D0ezGwengFHxQvQ-hBKXLD08W9VfzpzbH6r5JjhPotT85yPpPsxkxrd80ppkxphuYRlHCZk87vXfDBvcu8onuNhJf27Q-wlvydQ","e":"AQAB"}`,
			expectPrivErr: ErrPublic,
			expectPubPem: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsux5uN1IxBJcJzkKvw+w
hhZ6nilpQPdRPikVZHvysoTpO5qXlqfXWiZNX/Jbt+7wN0QvxROfiE1VYg05bXV+
6FWFkUug7bPwCno3YfxzfsHauPkzm0Agst6IrORClcRKAeACdsUJQJoNEa2Bo1K2
G8BRAAFDB+hV4ru7njM4Qs4iJMWyL80aNZrOkHXnYGn9n0bXTTRuxkJ4xwoLML12
6beTig2dn8iCxBXZdmNbzMhHun/sDi8D0ezGwengFHxQvQ+hBKXLD08W9VfzpzbH
6r5JjhPotT85yPpPsxkxrd80ppkxphuYRlHCZk87vXfDBvcu8onuNhJf27Q+wlvy
dQIDAQAB
-----END PUBLIC KEY-----
`,
		},
		{
			jsonData: `{"kty":"RSA","n":"sux5uN1IxBJcJzkKvw-whhZ6nilpQPdRPikVZHvysoTpO5qXlqfXWiZNX_Jbt-7wN0QvxROfiE1VYg05bXV-6FWFkUug7bPwCno3YfxzfsHauPkzm0Agst6IrORClcRKAeACdsUJQJoNEa2Bo1K2G8BRAAFDB-hV4ru7njM4Qs4iJMWyL80aNZrOkHXnYGn9n0bXTTRuxkJ4xwoLML126beTig2dn8iCxBXZdmNbzMhHun_sDi8D0ezGwengFHxQvQ-hBKXLD08W9VfzpzbH6r5JjhPotT85yPpPsxkxrd80ppkxphuYRlHCZk87vXfDBvcu8onuNhJf27Q-wlvydQ","e":"AQAB","d":"XgfdKIRS24hymcJmnWaXdMCXjEtjH1tafPqGXZquP5eOI17pT6nBiYUboNLz1MRjxge1uzLG4pER0Ef26EmZemyHl4ZRetrXygnU1VAhOnqSgielMXAQPzCoT4ReYesYoceiQ9zlMehD-ghfWv_66La3WvNO0PcPO-tBfLCaXrCpSRhCawwm3q_L9zhsLLIkJgE-CPwb4NNVh1fiV-bN4fnUFiIPdArdqoJAAPG0U1WN2BGVNE18UKgy1t5-HuPyRxk3oVAFbK3HPHDlhLx1dGaqKJXOG-TtyMch8YOzBStJm5WeisrzPFZgqUUajZFC0LJGNPAjq3jr8OwkXjp9-Q","p":"2xm3pujqmKd3D3ecdYyynG_Nx5YAApmwEQ5zw8WrbLhhT3pmVH7HpOZkn_43uOyn0jTm_LGslvJhS_fbDD_60Ph5pBX9Tj6Yn8FqVC6TS5-nAb0bSSbimK2hoL0Il2-jeRd50nP4TuwVF61i5BFiWqgEAEUlsg-d53CYolnEtUc","q":"0Q6U1XQtCuv3VpHWXzjMw9FCak4D0hIWWW4hNwXqpcy6m6Y9mDK4hKHyu7ZxytOQ98MOUadDZ9Ffx1L9WmIKW5PNA9NxH2jh9oKNHa7DqwY3xcNTKg-UnY5ekJnTnrYP-j2e0D7WOSOytPtyybsRyuKmmmJcyGUYFdDzhhezaGM","dp":"d51jsSDpqquKiYwwg9BrVpKHUpYmrUTAZZ9xPgk1nGZQ4fYd1bVdQz5w4xQD0daJjG5LSNurMMFksve-w8JOKTXuGtHSd5we8ODELu86hQfFQmK-ecJb5SSt37Yz8ZEGOz7AyE992YBzx3hmS8Ld4kZl4MvfV4XFHCxReBjwFlM","dq":"qgdH-Ytxju53zgry5aNWtvSdJcSpytM3JikyDoRbYdnu8-TzN7QY6pakyxMJ3cLQpxIXtUVqxyc81OqkcDxI3E6Lcc8otDkjftCTYU7giVqXRdsk6pKddr9yHf1eZjkBKa-wWQKiTPrBv_y6UWQ6hl5sziet-rZuLmAxkB_6pK0","qi":"N8TmYY5rLGS8GPIhzS66WSe6cc0qh0Gn7-fMc1dr_0pPOk0hckucMMHkwYFsujarRXqYDBgM8BZt2yv1ERJwOI0s8YomiLi99orQr45_69dH9P3yXLKYpQGuTYwznfsQ2ZrE8IUQV36gZV7_9uVyqKAmAgzMcVMWd_xMn7SNubk"}`,
			expectPubPem: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsux5uN1IxBJcJzkKvw+w
hhZ6nilpQPdRPikVZHvysoTpO5qXlqfXWiZNX/Jbt+7wN0QvxROfiE1VYg05bXV+
6FWFkUug7bPwCno3YfxzfsHauPkzm0Agst6IrORClcRKAeACdsUJQJoNEa2Bo1K2
G8BRAAFDB+hV4ru7njM4Qs4iJMWyL80aNZrOkHXnYGn9n0bXTTRuxkJ4xwoLML12
6beTig2dn8iCxBXZdmNbzMhHun/sDi8D0ezGwengFHxQvQ+hBKXLD08W9VfzpzbH
6r5JjhPotT85yPpPsxkxrd80ppkxphuYRlHCZk87vXfDBvcu8onuNhJf27Q+wlvy
dQIDAQAB
-----END PUBLIC KEY-----`,
			expectPrivPem: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsux5uN1IxBJcJzkKvw+whhZ6nilpQPdRPikVZHvysoTpO5qX
lqfXWiZNX/Jbt+7wN0QvxROfiE1VYg05bXV+6FWFkUug7bPwCno3YfxzfsHauPkz
m0Agst6IrORClcRKAeACdsUJQJoNEa2Bo1K2G8BRAAFDB+hV4ru7njM4Qs4iJMWy
L80aNZrOkHXnYGn9n0bXTTRuxkJ4xwoLML126beTig2dn8iCxBXZdmNbzMhHun/s
Di8D0ezGwengFHxQvQ+hBKXLD08W9VfzpzbH6r5JjhPotT85yPpPsxkxrd80ppkx
phuYRlHCZk87vXfDBvcu8onuNhJf27Q+wlvydQIDAQABAoIBAF4H3SiEUtuIcpnC
Zp1ml3TAl4xLYx9bWnz6hl2arj+XjiNe6U+pwYmFG6DS89TEY8YHtbsyxuKREdBH
9uhJmXpsh5eGUXra18oJ1NVQITp6koInpTFwED8wqE+EXmHrGKHHokPc5THoQ/oI
X1r/+ui2t1rzTtD3DzvrQXywml6wqUkYQmsMJt6vy/c4bCyyJCYBPgj8G+DTVYdX
4lfmzeH51BYiD3QK3aqCQADxtFNVjdgRlTRNfFCoMtbefh7j8kcZN6FQBWytxzxw
5YS8dXRmqiiVzhvk7cjHIfGDswUrSZuVnorK8zxWYKlFGo2RQtCyRjTwI6t46/Ds
JF46ffkCgYEA2xm3pujqmKd3D3ecdYyynG/Nx5YAApmwEQ5zw8WrbLhhT3pmVH7H
pOZkn/43uOyn0jTm/LGslvJhS/fbDD/60Ph5pBX9Tj6Yn8FqVC6TS5+nAb0bSSbi
mK2hoL0Il2+jeRd50nP4TuwVF61i5BFiWqgEAEUlsg+d53CYolnEtUcCgYEA0Q6U
1XQtCuv3VpHWXzjMw9FCak4D0hIWWW4hNwXqpcy6m6Y9mDK4hKHyu7ZxytOQ98MO
UadDZ9Ffx1L9WmIKW5PNA9NxH2jh9oKNHa7DqwY3xcNTKg+UnY5ekJnTnrYP+j2e
0D7WOSOytPtyybsRyuKmmmJcyGUYFdDzhhezaGMCgYB3nWOxIOmqq4qJjDCD0GtW
kodSliatRMBln3E+CTWcZlDh9h3VtV1DPnDjFAPR1omMbktI26swwWSy977Dwk4p
Ne4a0dJ3nB7w4MQu7zqFB8VCYr55wlvlJK3ftjPxkQY7PsDIT33ZgHPHeGZLwt3i
RmXgy99XhcUcLFF4GPAWUwKBgQCqB0f5i3GO7nfOCvLlo1a29J0lxKnK0zcmKTIO
hFth2e7z5PM3tBjqlqTLEwndwtCnEhe1RWrHJzzU6qRwPEjcTotxzyi0OSN+0JNh
TuCJWpdF2yTqkp12v3Id/V5mOQEpr7BZAqJM+sG//LpRZDqGXmzOJ636tm4uYDGQ
H/qkrQKBgDfE5mGOayxkvBjyIc0uulknunHNKodBp+/nzHNXa/9KTzpNIXJLnDDB
5MGBbLo2q0V6mAwYDPAWbdsr9REScDiNLPGKJoi4vfaK0K+Of+vXR/T98lyymKUB
rk2MM537ENmaxPCFEFd+oGVe//blcqigJgIMzHFTFnf8TJ+0jbm5
-----END RSA PRIVATE KEY-----
`,
		},
	}

	as := assert.New(t)
	for _, tst := range cases {
		var j JWK
		require.NoError(t, json.Unmarshal([]byte(tst.jsonData), &j))

		priv, err := j.PrivateKey()
		as.Equal(tst.expectPrivErr, err)

		var expect interface{}
		if tst.expectPrivPem != "" {
			expect, err = parsePrivateKey([]byte(tst.expectPrivPem))
			require.NoError(t, err)
		} else {
			expect = tst.expectPriv
		}
		as.Equal(expect, priv)

		if expect != nil {
			jj, err := EncodePrivateKey(expect.(cryptoutils.PrivateKey))
			require.NoError(t, err)
			as.Equal(&j, jj)
		}

		pub, err := j.PublicKey()
		as.Equal(tst.expectPubErr, err)

		if tst.expectPubPem != "" {
			expect, err = parsePublicKey([]byte(tst.expectPubPem))
			require.NoError(t, err)
		} else {
			expect = tst.expectPub
		}
		as.Equal(expect, pub)
	}
}
