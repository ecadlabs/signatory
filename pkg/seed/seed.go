package seed

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ecadlabs/hdw"
	"github.com/ecadlabs/hdw/bip25519"
	"github.com/ecadlabs/hdw/bip25519/ex25519"
	"github.com/ecadlabs/hdw/ecdsa"
	"github.com/ecadlabs/signatory/pkg/tezos"
)

var seedData = "sense defy yellow arch cotton describe unit hill time unusual drip banana drum inspire wear recycle senior journey spend apple myth royal social again"

func DerivePk(s []byte, path string, method string, hmac bool) (string, error) {
	var sk, p string

	sd := strings.Split(string(s), " ")
	if len(sd) > 1 {
		if path == "" || method == "" {
			return "", fmt.Errorf("private key derivation path and derivation method required")
		}
		hp, err := hdw.ParsePath(p)
		if err != nil {
			return "", err
		}
		switch method {
		case "slip10":
			sk, err = slip10(string(s), hp)
			if err != nil {
				return "", err
			}
		case "bip32":
			sk, err = bip32(string(s), hp)
			if err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("unknown derivation method")
		}

	} else {
		sk = string(s)
	}
	return sk, nil
}

func slip10(sd string, path hdw.Path) (string, error) {
	// alternatively use hdw.NewSeedFromMnemonic
	seed, err := hex.DecodeString(seedData)
	if err != nil {
		panic(err)
	}

	// generate the root key
	root, err := ecdsa.NewKeyFromSeed(seed, elliptic.P256())
	if err != nil {
		panic(err)
	}

	// generate the derivative child private key
	priv, err := root.DerivePath(path)
	if err != nil {
		panic(err)
	}

	spk, err := tezos.EncodePrivateKey(priv.Naked().(ex25519.PrivateKey))
	if err != nil {
		return "", err
	}
	return spk, nil
}

func bip32(sd string, path hdw.Path) (string, error) {
	fmt.Println("Lib test of HDW with phrase: ", seedData)
	seed := hdw.NewSeedFromMnemonic(sd, "")
	fmt.Println("Seed: ", string(seed))

	// generate the root key
	root := bip25519.NewKeyFromSeed(seed, nil)
	if root == nil {
		panic("unusable seed")
	}

	// generate the derivative child private key
	priv, err := root.DerivePath(path)
	if err != nil {
		panic(err)
	}

	spk, err := tezos.EncodePrivateKey(priv.Naked().(ex25519.PrivateKey))
	if err != nil {
		return "", err
	}
	return spk, nil
}
