package ledger

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/ledger/ledger"
	"github.com/ecadlabs/signatory/pkg/vault/ledger/tezosapp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type device struct {
	info    *ledger.DeviceInfo
	version *tezosapp.Version
	id      string
	shortID string
}

type deviceScanner struct {
	mtx sync.Mutex
	tr  ledger.Transport
}

func (s *deviceScanner) scan() ([]*device, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	devs, err := s.tr.Enumerate()
	if err != nil {
		return nil, err
	}

	res := make([]*device, 0, len(devs))
	for _, d := range devs {
		ex, err := s.tr.Open(d.Path)
		if err != nil {
			return nil, err
		}
		app := tezosapp.TezosApp{Exchanger: ex}

		ver, err := app.GetVersion()
		if err != nil {
			continue // App is not running
		}

		rootPK, err := app.GetPublicKey(tezosapp.DerivationED25519, tezosapp.TezosBIP32Root, false)
		if err != nil {
			return nil, err
		}

		hash, err := tezos.GetPublicKeyHash(rootPK)
		if err != nil {
			return nil, err
		}

		pkh, err := tezos.EncodePublicKeyHash(rootPK)
		if err != nil {
			return nil, err
		}

		res = append(res, &device{
			info:    d,
			version: ver,
			id:      pkh,
			shortID: hex.EncodeToString(hash[:4]),
		})
	}
	return res, nil
}

var (
	transport = ledger.USBHIDTransport{}
	scanner   = deviceScanner{
		tr: &transport,
	}
)

type Vault struct {
}

type ledgerKey struct {
	path tezosapp.BIP32
	pub  crypto.PublicKey
}

func (l *ledgerKey) PublicKey() crypto.PublicKey { return l.pub }
func (l *ledgerKey) ID() string                  { return l.path.String() }

type ledgerIterator struct {
	// TODO
}

func (l *ledgerIterator) Next() (key vault.StoredKey, err error) {
	return nil, vault.ErrDone // TODO
}

func (v *Vault) GetPublicKey(ctx context.Context, id string) (vault.StoredKey, error) {
	return nil, errors.New("stub")
}

func (v *Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	return &ledgerIterator{} // TODO
}

func (v *Vault) Sign(ctx context.Context, digest []byte, key vault.StoredKey) (cryptoutils.Signature, error) {
	return nil, errors.New("stub")
}

func (v *Vault) Name() string {
	return "Ledger"
}

func New(ctx context.Context) (*Vault, error) {
	devs, err := scanner.scan()
	if err != nil {
		return nil, err
	}

	for _, d := range devs {
		log.WithFields(log.Fields{
			"path":     d.info.Path,
			"id":       d.id,
			"short_id": d.shortID,
		}).Infof("Found Ledger running %v", d.version)
	}

	return &Vault{}, nil
}

func init() {
	vault.RegisterVault("ledger", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
		return New(ctx)
	})
}
