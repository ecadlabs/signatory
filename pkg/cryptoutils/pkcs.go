package cryptoutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1"
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

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch {
	case curve == elliptic.P224():
		return oidNamedCurveP224, true
	case curve == elliptic.P256():
		return oidNamedCurveP256, true
	case curve == elliptic.P384():
		return oidNamedCurveP384, true
	case curve == elliptic.P521():
		return oidNamedCurveP521, true
	case curve == S256() || curve == secp256k1.S256() || CurveEqual(curve, S256()):
		return oidNamedCurveS256, true
	}

	return nil, false
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
//   RFC 5915
//   SEC1 - http://www.secg.org/sec1-v2.pdf
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

	oid, ok := oidFromNamedCurve(key.Curve)
	if !ok {
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

// MarshalPKCS8PrivateKey converts aprivate key to PKCS#8, ASN.1 DER form.
func MarshalPKCS8PrivateKey(key interface{}) ([]byte, error) {
	if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
		return marshalPKCS8ECDSAPrivateKey(ecdsaKey)
	}
	return x509.MarshalPKCS8PrivateKey(key)
}
