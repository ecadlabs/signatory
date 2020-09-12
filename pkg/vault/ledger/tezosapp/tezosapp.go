package tezosapp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/vault/ledger/ledger"
)

// TezosApp represents Tezos application client
type TezosApp struct {
	ledger.App
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
	return fmt.Sprintf("%s %d.%d.%d", class, v.Major, v.Minor, v.Patch)
}

// GetVersion returns Tezos app version
func (t *TezosApp) GetVersion() (*Version, error) {
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
	return &Version{
		AppClass: res.Data[0],
		Major:    res.Data[1],
		Minor:    res.Data[2],
		Patch:    res.Data[3],
	}, nil
}

// Curve types with different derivation methods
const (
	DerivationTypeED25519 = iota
	DerivationTypeSECP256K1
	DerivationTypeSECP256R1
	DerivationTypeBIP32ED25519
	DerivationTypeP256 = DerivationTypeSECP256R1
)

// TezosBIP32Root is a Tezos BIP32 root key path i.e. 44'/1729'
var TezosBIP32Root = BIP32{44 | BIP32H, 1729 | BIP32H}

const (
	tagCompressed   = 2
	tagUncompressed = 4
)

// GetPublicKey returns a public key for a newly derived pair
func (t *TezosApp) GetPublicKey(derivation uint8, path BIP32, prompt bool) (pub crypto.PublicKey, err error) {
	var ins uint8
	if prompt {
		ins = insPromptPublicKey
	} else {
		ins = insGetPublicKey
	}
	res, err := t.Exchange(&ledger.APDUCommand{
		Cla:  claTezos,
		Ins:  ins,
		P2:   derivation,
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
	case DerivationTypeED25519, DerivationTypeBIP32ED25519:
		if comp != tagCompressed {
			return nil, fmt.Errorf("invalid compression tag: %d", comp)
		}
		if len(data) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid public key length: %d", len(data))
		}
		return ed25519.PublicKey(data), nil

	case DerivationTypeSECP256K1, DerivationTypeSECP256R1:
		if comp != tagUncompressed {
			return nil, fmt.Errorf("invalid compression tag: %d", comp)
		}
		if len(data) != 64 {
			return nil, fmt.Errorf("invalid public key length: %d", len(data))
		}

		var curve elliptic.Curve
		if derivation == DerivationTypeSECP256K1 {
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
