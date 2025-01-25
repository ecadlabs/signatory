package x509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	encoding_asn1 "encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/ecadlabs/gotez/v2/crypt"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidPublicKeyECDSA   = encoding_asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPublicKeyEd25519 = encoding_asn1.ObjectIdentifier{1, 3, 101, 112}

	oidNamedCurveP224 = encoding_asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = encoding_asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = encoding_asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = encoding_asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveS256 = encoding_asn1.ObjectIdentifier{1, 3, 132, 0, 10} // http://www.secg.org/sec2-v2.pdf
)

func namedCurveFromOID(oid encoding_asn1.ObjectIdentifier) elliptic.Curve {
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
		return crypt.S256()
	}
	return nil
}

func oidFromNamedCurve(curve elliptic.Curve) encoding_asn1.ObjectIdentifier {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224
	case elliptic.P256():
		return oidNamedCurveP256
	case elliptic.P384():
		return oidNamedCurveP384
	case elliptic.P521():
		return oidNamedCurveP521
	case crypt.S256():
		return oidNamedCurveS256
	default:
		return nil
	}
}

func parseECDSAPrivateKey(curveOid encoding_asn1.ObjectIdentifier, data []byte) (key any, err error) {
	der := cryptobyte.String(data)
	var (
		obj, keyData cryptobyte.String
		ver          int
		curvePresent bool
		optCurveData cryptobyte.String
		optCurveOid  encoding_asn1.ObjectIdentifier
	)

	if !der.ReadASN1(&obj, asn1.SEQUENCE) ||
		!obj.ReadASN1Integer(&ver) ||
		!obj.ReadASN1(&keyData, asn1.OCTET_STRING) ||
		!obj.ReadOptionalASN1(&optCurveData, &curvePresent, 0) ||
		curvePresent && !optCurveData.ReadASN1ObjectIdentifier(&optCurveOid) {
		return nil, errors.New("x509: failed to parse EC private key")
	}
	if curveOid == nil {
		if curvePresent {
			curveOid = optCurveOid
		} else {
			return nil, errors.New("x509: missing curve OID")
		}
	}
	curve := namedCurveFromOID(curveOid)
	if curve == nil {
		return nil, fmt.Errorf("x509: unknown curve: %v", curveOid)
	}

	priv := make([]byte, (curve.Params().N.BitLen()+7)/8)
	for len(keyData) > len(priv) {
		if keyData[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		keyData = keyData[1:]
	}
	copy(priv[len(priv)-len(keyData):], keyData)

	d := new(big.Int).SetBytes(priv)
	if d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("x509: invalid EC private key")
	}

	out := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: d,
	}
	out.X, out.Y = curve.ScalarBaseMult(priv)
	return &out, nil
}

func ParsePKCS8PrivateKey(der []byte) (key any, err error) {
	src := cryptobyte.String(der)
	var (
		obj, algo, keyData cryptobyte.String
		algoOid            encoding_asn1.ObjectIdentifier
		ver                int
	)

	if !src.ReadASN1(&obj, asn1.SEQUENCE) ||
		!obj.ReadASN1Integer(&ver) ||
		!obj.ReadASN1(&algo, asn1.SEQUENCE) ||
		!algo.ReadASN1ObjectIdentifier(&algoOid) ||
		!obj.ReadASN1(&keyData, asn1.OCTET_STRING) {
		return nil, errors.New("x509: failed to parse PKCS#8 private key")
	}

	switch {
	case algoOid.Equal(oidPublicKeyECDSA):
		var curve encoding_asn1.ObjectIdentifier
		if algo.PeekASN1Tag(asn1.OBJECT_IDENTIFIER) {
			if !algo.ReadASN1ObjectIdentifier(&curve) {
				return nil, errors.New("x509: failed to parse EC OID")
			}
		}
		return parseECDSAPrivateKey(curve, keyData)

	case algoOid.Equal(oidPublicKeyEd25519):
		der := cryptobyte.String(keyData)
		var priv cryptobyte.String
		if !der.ReadASN1(&priv, asn1.OCTET_STRING) {
			return nil, errors.New("x509: failed to parse Ed25519 private key")
		}
		if len(priv) != ed25519.SeedSize {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key length: %d", len(priv))
		}
		return ed25519.NewKeyFromSeed(priv), nil

	default:
		return nil, fmt.Errorf("x509: unsupported algorithm: %v", algo)
	}
}

func ParsePKIXPublicKey(der []byte) (pub any, err error) {
	src := cryptobyte.String(der)
	var (
		obj, algo cryptobyte.String
		algoOid   encoding_asn1.ObjectIdentifier
		keyData   encoding_asn1.BitString
	)

	if !src.ReadASN1(&obj, asn1.SEQUENCE) ||
		!obj.ReadASN1(&algo, asn1.SEQUENCE) ||
		!algo.ReadASN1ObjectIdentifier(&algoOid) ||
		!obj.ReadASN1BitString(&keyData) {
		return nil, errors.New("x509: failed to parse PKIX public key")
	}

	keyBytes := keyData.RightAlign()
	switch {
	case algoOid.Equal(oidPublicKeyECDSA):
		var curveOid encoding_asn1.ObjectIdentifier
		if algo.PeekASN1Tag(asn1.OBJECT_IDENTIFIER) {
			if !algo.ReadASN1ObjectIdentifier(&curveOid) {
				return nil, errors.New("x509: failed to parse EC OID")
			}
		}
		curve := namedCurveFromOID(curveOid)
		if curve == nil {
			return nil, fmt.Errorf("x509: unknown curve: %v", curveOid)
		}
		x, y := elliptic.Unmarshal(curve, keyBytes)
		if x == nil {
			return nil, errors.New("x509: invalid EC point")
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, nil

	case algoOid.Equal(oidPublicKeyEd25519):
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("x509: invalid Ed25519 public key length: %d", len(keyBytes))
		}
		return ed25519.PublicKey(keyBytes), nil

	default:
		return nil, fmt.Errorf("x509: unsupported algorithm: %v", algo)
	}
}

func MarshalPKCS8PrivateKey(key any) (res []byte, err error) {
	var (
		b        cryptobyte.Builder
		curveOid encoding_asn1.ObjectIdentifier
	)
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0) // version
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			switch k := key.(type) {
			case *ecdsa.PrivateKey:
				b.AddASN1ObjectIdentifier(oidPublicKeyECDSA)
				if curveOid = oidFromNamedCurve(k.Curve); curveOid == nil {
					b.SetError(fmt.Errorf("x509: unknown curve: %T", k.Curve))
					return
				}
				b.AddASN1ObjectIdentifier(curveOid)

			case ed25519.PrivateKey:
				b.AddASN1ObjectIdentifier(oidPublicKeyEd25519)

			default:
				b.SetError(fmt.Errorf("x509: unsupported private key type %T", k))
				return
			}
		})

		var keyData cryptobyte.Builder
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			priv := make([]byte, (k.Curve.Params().N.BitLen()+7)/8)
			k.D.FillBytes(priv)
			keyData.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1) // version
				b.AddASN1OctetString(priv)
				b.AddASN1(0, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(curveOid)
				})
				b.AddASN1(1, func(b *cryptobyte.Builder) {
					b.AddASN1BitString(elliptic.Marshal(k.Curve, k.X, k.Y))
				})
			})
		case ed25519.PrivateKey:
			keyData.AddASN1OctetString(k.Seed())

		default:
			b.SetError(fmt.Errorf("x509: unsupported private key type %T", k))
			return
		}

		keyBytes, err := keyData.Bytes()
		if err != nil {
			b.SetError(err)
			return
		}
		b.AddASN1OctetString(keyBytes)
	})
	return b.Bytes()
}
