package ledger

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/vault/ledger/ledger"
	"github.com/ecadlabs/signatory/pkg/vault/ledger/tezosapp"
)

type deviceInfo struct {
	Path    string
	Version *tezosapp.Version
	ID      string
	ShortID string
}

type scanner struct {
	mtx sync.Mutex
	tr  ledger.Transport
}

func (s *scanner) openPath(path string) (app *tezosapp.App, dev *deviceInfo, err error) {
	ex, err := s.tr.Open(path)
	if err != nil {
		return nil, nil, err
	}
	app = &tezosapp.App{Exchanger: ex}

	defer func(a *tezosapp.App) {
		if err != nil {
			a.Close()
		}
	}(app)

	ver, err := app.GetVersion()
	if err != nil {
		return nil, nil, err
	}

	rootPK, err := app.GetPublicKey(tezosapp.DerivationED25519, tezosapp.TezosBIP32Root, false)
	if err != nil {
		return nil, nil, err
	}

	hash, err := tezos.GetPublicKeyHash(rootPK)
	if err != nil {
		return nil, nil, err
	}

	pkh, err := tezos.EncodePublicKeyHash(rootPK)
	if err != nil {
		return nil, nil, err
	}

	dev = &deviceInfo{
		Path:    path,
		Version: ver,
		ID:      pkh,
		ShortID: hex.EncodeToString(hash[:4]),
	}
	return app, dev, nil
}

func (s *scanner) open(id string) (*tezosapp.App, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	devs, err := s.tr.Enumerate()
	if err != nil {
		return nil, err
	}

	if len(devs) == 0 {
		return nil, errors.New("no Ledger devices found")
	}

	for _, d := range devs {
		app, dev, err := s.openPath(d.Path)
		if err != nil {
			continue
		}
		if id == "" || dev.ShortID == id || dev.ID == id {
			return app, nil
		}
		if err := app.Close(); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("can't find a device with id %s", id)
}

func (s *scanner) scan() ([]*deviceInfo, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	devs, err := s.tr.Enumerate()
	if err != nil {
		return nil, err
	}

	res := make([]*deviceInfo, 0, len(devs))
	for _, d := range devs {
		app, dev, err := s.openPath(d.Path)
		if err != nil {
			continue
		}
		app.Close()
		res = append(res, dev)
	}
	return res, nil
}
