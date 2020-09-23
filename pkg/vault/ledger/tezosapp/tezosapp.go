package tezosapp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/vault/ledger/ledger"
)

// App represents Tezos application client
type App struct {
	ledger.Exchanger
}

// Tezos application types
const (
	AppTezos   = 0
	AppTezBake = 1
)

// Version contains Tezos app version
type Version struct {
	AppClass uint8
	Major    uint8
	Minor    uint8
	Patch    uint8
	Git      string
}

func (v *Version) String() string {
	var class string
	switch v.AppClass {
	case AppTezos:
		class = "Tezos"
	case AppTezBake:
		class = "TezBake"
	default:
		class = "Unknown"
	}
	return fmt.Sprintf("%s %d.%d.%d %s", class, v.Major, v.Minor, v.Patch, v.Git)
}

// GetVersion returns Tezos app version
func (t *App) GetVersion() (*Version, error) {
	res, err := t.Exchange(&ledger.APDUCommand{
		Cla:     claTezos,
		Ins:     insVersion,
		ForceLc: true,
	})
	if err != nil {
		return nil, err
	}
	if res.SW != errOk {
		return nil, TezosError(res.SW)
	}
	if len(res.Data) < 4 {
		return nil, errors.New("invalid version length")
	}
	ver := Version{
		AppClass: res.Data[0],
		Major:    res.Data[1],
		Minor:    res.Data[2],
		Patch:    res.Data[3],
	}

	res, err = t.Exchange(&ledger.APDUCommand{
		Cla:     claTezos,
		Ins:     insGit,
		ForceLc: true,
	})
	if err != nil {
		return nil, err
	}
	if res.SW != errOk {
		return nil, TezosError(res.SW)
	}
	ver.Git = string(res.Data)

	return &ver, nil
}

// DerivationType represents key derivation method and determines the curve to use
type DerivationType uint8

const (
	DerivationED25519      DerivationType = iota                // ED25519
	DerivationSECP256K1                                         // SECP256K1
	DerivationSECP256R1                                         // SECP256R1 aka P256
	DerivationBIP32ED25519                                      // BIP32-ED25519
	DerivationP256                        = DerivationSECP256R1 // SECP256R1 aka P256
	DerivationInvalid      DerivationType = 0xff
)

func (d DerivationType) String() string {
	switch d {
	case DerivationED25519:
		return "ed25519"
	case DerivationSECP256K1:
		return "secp256k1"
	case DerivationSECP256R1:
		return "P-256"
	case DerivationBIP32ED25519:
		return "bip32-ed25519"
	default:
		return fmt.Sprintf("(%d)", uint8(d))
	}
}

// DerivationTypeFromString returns a derivation type id for specified name
func DerivationTypeFromString(str string) (DerivationType, error) {
	switch strings.ToLower(str) {
	case "ed25519":
		return DerivationED25519, nil
	case "secp256k1":
		return DerivationSECP256K1, nil
	case "p-256", "secp256r1":
		return DerivationSECP256R1, nil
	case "bip25519", "bip32-ed25519":
		return DerivationBIP32ED25519, nil
	default:
		return DerivationInvalid, fmt.Errorf("unknown key derivation type: %s", str)
	}
}

// TezosBIP32Root is a Tezos BIP32 root key path i.e. 44'/1729'
var TezosBIP32Root = BIP32{44 | BIP32H, 1729 | BIP32H}

const (
	tagCompressed   = 2
	tagUncompressed = 4
)

func pathValid(path BIP32) error {
	for _, p := range path {
		if p&BIP32H == 0 {
			return errors.New("only hardened derivation supported")
		}
	}
	return nil
}

// GetPublicKey returns a public key for a newly derived pair
func (t *App) GetPublicKey(derivation DerivationType, path BIP32, prompt bool) (pub crypto.PublicKey, err error) {
	ins := insGetPublicKey
	if prompt {
		ins = insPromptPublicKey
	}

	if err := pathValid(path); err != nil {
		return nil, err
	}

	res, err := t.Exchange(&ledger.APDUCommand{
		Cla:  claTezos,
		Ins:  uint8(ins),
		P2:   uint8(derivation),
		Data: path.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	if res.SW != errOk {
		return nil, TezosError(res.SW)
	}

	if len(res.Data) < 2 {
		return nil, errors.New("public key reply is too short")
	}

	ln := int(res.Data[0])
	comp := res.Data[1] // LCX specific compression tag
	if ln > len(res.Data)-1 {
		return nil, errors.New("invalid public key reply length")
	}
	data := res.Data[2 : ln+1]

	switch derivation {
	case DerivationED25519, DerivationBIP32ED25519:
		if comp != tagCompressed {
			return nil, fmt.Errorf("invalid compression tag: %d", comp)
		}
		if len(data) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid public key length: %d", len(data))
		}
		return ed25519.PublicKey(data), nil

	case DerivationSECP256K1, DerivationSECP256R1:
		if comp != tagUncompressed {
			return nil, fmt.Errorf("invalid compression tag: %d", comp)
		}
		if len(data) != 64 {
			return nil, fmt.Errorf("invalid public key length: %d", len(data))
		}

		var curve elliptic.Curve
		if derivation == DerivationSECP256K1 {
			curve = cryptoutils.S256()
		} else {
			curve = elliptic.P256()
		}

		x := new(big.Int).SetBytes(data[:32])
		y := new(big.Int).SetBytes(data[32:])

		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("point is not on %s", curve.Params().Name)
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, nil

	default:
		return nil, fmt.Errorf("invalid derivation type: %d", derivation)
	}
}

// fragmentation is handled by the app itself and varies between different apps
const maxAPDUSize = 230

const (
	p1Next = 0x01
	p1Last = 0x80
)

// Sign signs the message or precalculated hash
func (t *App) Sign(derivation DerivationType, path BIP32, data []byte, prehashed bool) (sig cryptoutils.Signature, err error) {
	ins := insSign
	if prehashed {
		ins = insSignUnsafe
	}

	apdu := ledger.APDUCommand{
		Cla:  claTezos,
		Ins:  uint8(ins),
		P2:   uint8(derivation),
		Data: path.Bytes(),
	}
	res, err := t.Exchange(&apdu)
	if err != nil {
		return nil, err
	}
	if res.SW != errOk {
		return nil, TezosError(res.SW)
	}

	off := 0
	apdu.P1 = p1Next

	for off < len(data) {
		sz := maxAPDUSize
		if sz > len(data)-off {
			sz = len(data) - off
		}
		apdu.Data = data[off : off+sz]
		off += sz
		if off == len(data) {
			apdu.P1 |= p1Last
		}
		if res, err = t.Exchange(&apdu); err != nil {
			return nil, err
		}
		if res.SW != errOk {
			return nil, TezosError(res.SW)
		}
	}

	switch derivation {
	case DerivationED25519, DerivationBIP32ED25519:
		if len(res.Data) != ed25519.SignatureSize {
			return nil, fmt.Errorf("invalid signature length: %d", len(res.Data))
		}
		return cryptoutils.ED25519Signature(res.Data), nil

	case DerivationSECP256K1, DerivationSECP256R1:
		/*
			var curve elliptic.Curve
			if derivation == DerivationSECP256K1 {
				curve = cryptoutils.S256()
			} else {
				curve = elliptic.P256()
			}
		*/

		if len(res.Data) != 0 {
			// remove the parity flag which interfere with ASN.1
			// see https://github.com/obsidiansystems/ledger-app-tezos/blob/58797b2f9606c5a30dd1ccc9e5b9962e45e10356/src/keys.c#L176
			res.Data[0] &= 0xfe
		}
		var sig struct {
			R *big.Int
			S *big.Int
		}
		if _, err = asn1.Unmarshal(res.Data, &sig); err != nil {
			return nil, err
		}
		return (*cryptoutils.ECDSASignature)(&sig), nil // TODO curve type

	default:
		return nil, fmt.Errorf("invalid derivation type: %d", derivation)
	}
}
