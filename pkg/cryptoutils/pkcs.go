package cryptoutils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ecadlabs/gotez/v2/crypt"
	"golang.org/x/crypto/cryptobyte"
)

// partially copied from crypto/x509

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveS256 = asn1.ObjectIdentifier{1, 3, 132, 0, 10} // http://www.secg.org/sec2-v2.pdf

	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

func oidFromNamedCurve(curve elliptic.Curve) asn1.ObjectIdentifier {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224
	case elliptic.P256():
		return oidNamedCurveP256
	case elliptic.P384():
		return oidNamedCurveP384
	case elliptic.P521():
		return oidNamedCurveP521
	case secp256k1.S256():
		return oidNamedCurveS256
	default:
		return nil
	}
}

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

// ecPrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
// References:
//
//	RFC 5915
//	SEC1 - http://www.secg.org/sec1-v2.pdf
//
// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func marshalPKCS8ECDSAPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	var privKey pkcs8

	oid := oidFromNamedCurve(key.Curve)
	if oid == nil {
		return nil, errors.New("cryptoutils: unknown curve while marshaling to PKCS#8: " + key.Curve.Params().Name)
	}

	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, errors.New("cryptoutils: failed to marshal curve OID: " + err.Error())
	}

	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidPublicKeyECDSA,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}

	if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(key, nil); err != nil {
		return nil, errors.New("cryptoutils: failed to marshal EC private key while building PKCS#8: " + err.Error())
	}

	return asn1.Marshal(privKey)
}

// marshalECPrivateKey marshals an EC private key into ASN.1, DER format and
// sets the curve ID to the given OID, or omits it if OID is nil.
func marshalECPrivateKeyWithOID(key *ecdsa.PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
	privateKeyBytes := key.D.Bytes()
	paddedPrivateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)

	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    paddedPrivateKey,
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}

// MarshalPKCS8PrivateKey converts a private key to PKCS#8, ASN.1 DER form.
func MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	switch key := key.(type) {
	case *crypt.ECDSAPrivateKey:
		return marshalPKCS8ECDSAPrivateKey((*ecdsa.PrivateKey)(key))
	case *ecdsa.PrivateKey:
		return marshalPKCS8ECDSAPrivateKey(key)
	case crypt.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(key.Unwrap())
	default:
		return x509.MarshalPKCS8PrivateKey(key)
	}
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	case oid.Equal(oidNamedCurveS256):
		return secp256k1.S256()
	}
	return nil
}

func parseECDSAPublicKey(keyData *publicKeyInfo) (any, error) {
	der := cryptobyte.String(keyData.PublicKey.RightAlign())
	paramsDer := cryptobyte.String(keyData.Algorithm.Parameters.FullBytes)
	namedCurveOID := new(asn1.ObjectIdentifier)
	if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
		return nil, errors.New("x509: invalid ECDSA parameters")
	}
	namedCurve := namedCurveFromOID(*namedCurveOID)
	if namedCurve == nil {
		return nil, errors.New("x509: unsupported elliptic curve")
	}
	x, y := elliptic.Unmarshal(namedCurve, der)
	if x == nil {
		return nil, errors.New("x509: failed to unmarshal elliptic curve point")
	}
	pub := &ecdsa.PublicKey{
		Curve: namedCurve,
		X:     x,
		Y:     y,
	}
	return pub, nil
}

func ParsePKIXPublicKey(derBytes []byte) (pub any, err error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}

	if pki.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		return parseECDSAPublicKey(&pki)
	} else {
		return x509.ParsePKIXPublicKey(derBytes)
	}
}

// ParsePKCS8PrivateKey wraps standard library function and returns a wrapped private key.
// Secp256k1 is NOT supported
func ParsePKCS8PrivateKey(der []byte) (crypt.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}

	switch key := key.(type) {
	case ed25519.PrivateKey:
		return crypt.Ed25519PrivateKey(key), nil
	case *ecdsa.PrivateKey:
		if key.Curve == elliptic.P256() {
			return (*crypt.ECDSAPrivateKey)(key), nil
		} else {
			return nil, fmt.Errorf("unsupported curve: %v", key.Curve.Params())
		}
	default:
		return nil, fmt.Errorf("unsupported PKCS#8 key type: %T", key)
	}
}
