package cryptoutils

import (
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/cryptoutils/x509"
)

func MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	switch key := key.(type) {
	case crypt.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(key.Unwrap())
	default:
		return x509.MarshalPKCS8PrivateKey(key)
	}
}

// ParsePKCS8PrivateKey wraps standard library function and returns a wrapped private key.
func ParsePKCS8PrivateKey(der []byte) (crypt.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	return crypt.NewPrivateKeyFrom(key)
}

func ParsePKIXPublicKey(der []byte) (crypt.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	return crypt.NewPublicKeyFrom(key)
}
