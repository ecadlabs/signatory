package ledger

import (
	"github.com/ecadlabs/gotez"
	"github.com/ecadlabs/gotez/b58"
	"github.com/ecadlabs/signatory/pkg/vault/ledger/tezosapp"
)

// Utility functions used by CLI

func SetupBaking(transport string, id, keyID, chainID string, mainHWM, testHWM uint32) (pkh string, err error) {
	var hwm tezosapp.HWM
	if chainID != "" {
		cid, err := b58.ParseChainID([]byte(chainID))
		if err != nil {
			return "", err
		}
		hwm.ChainID = *cid
	}
	key, err := parseKeyID(keyID)
	if err != nil {
		return "", err
	}
	s, err := getScanner(transport)
	if err != nil {
		return
	}
	dev, err := s.open(id)
	if err != nil {
		return "", err
	}
	defer dev.Close()

	pub, err := dev.SetupBaking(&hwm, key.dt, key.path)
	if err != nil {
		return "", err
	}
	return pub.Hash().String(), nil
}

func DeauthorizeBaking(transport string, id string) error {
	s, err := getScanner(transport)
	if err != nil {
		return err
	}
	dev, err := s.open(id)
	if err != nil {
		return err
	}
	defer dev.Close()
	err = dev.DeauthorizeBaking()
	if err != nil {
		return err
	}
	return nil
}

func SetHighWatermark(transport string, id string, hwm uint32) error {
	s, err := getScanner(transport)
	if err != nil {
		return err
	}
	dev, err := s.open(id)
	if err != nil {
		return err
	}
	defer dev.Close()
	return dev.SetHighWatermark(hwm)
}

func GetHighWatermark(transport string, id string) (hwm uint32, err error) {
	s, err := getScanner(transport)
	if err != nil {
		return
	}
	dev, err := s.open(id)
	if err != nil {
		return
	}
	defer dev.Close()
	return dev.GetHighWatermark()
}

func GetHighWatermarks(transport string, id string) (mainHWM, testHWM uint32, chainID string, err error) {
	s, err := getScanner(transport)
	if err != nil {
		return
	}
	dev, err := s.open(id)
	if err != nil {
		return
	}
	defer dev.Close()
	hwm, err := dev.GetHighWatermarks()
	if err != nil {
		return
	}
	return hwm.Main, hwm.Test, gotez.ChainID(hwm.ChainID).String(), nil
}
