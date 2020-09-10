package tezosapp

import (
	"errors"
	"fmt"

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
