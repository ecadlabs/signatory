package ledger

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/ledger/ledger"
	"github.com/ecadlabs/signatory/pkg/vault/ledger/tezosapp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const defaultCloseAfter = time.Second * 10

var (
	transport     = ledger.USBHIDTransport{}
	deviceScanner = scanner{
		tr: &transport,
	}
)

type devRequest interface {
	devRequest()
}

type getKeyReq struct {
	key *keyID
	res chan<- *ledgerKey
	err chan<- error
}

func (g *getKeyReq) devRequest() {}

type signReq struct {
	key  *keyID
	data []byte

	sig chan<- cryptoutils.Signature
	err chan<- error
}

func (s *signReq) devRequest() {}

type keyID struct {
	path tezosapp.BIP32
	dt   tezosapp.DerivationType
}

// Vault is a Ledger signer backend
type Vault struct {
	config Config
	keys   []*keyID
	req    chan devRequest
}

// Config represents Ledger signer backend configuration
type Config struct {
	ID         string        `yaml:"id"`
	Keys       []string      `yaml:"keys"`
	CloseAfter time.Duration `yaml:"close_after"`
}

type ledgerKey struct {
	id  *keyID
	pub crypto.PublicKey
}

func (l *ledgerKey) PublicKey() crypto.PublicKey { return l.pub }
func (l *ledgerKey) ID() string                  { return l.id.String() }

type ledgerIterator struct {
	ctx context.Context
	v   *Vault
	idx int
}

func (l *ledgerIterator) Next() (key vault.StoredKey, err error) {
	if l.idx == len(l.v.keys) {
		return nil, vault.ErrDone
	}

	pk, err := l.v.getPublicKey(l.ctx, l.v.keys[l.idx])
	if err != nil {
		return nil, err
	}
	l.idx++

	return pk, nil
}

func (v *Vault) getPublicKey(ctx context.Context, id *keyID) (vault.StoredKey, error) {
	res := make(chan *ledgerKey, 1)
	errCh := make(chan error, 1)

	v.req <- &getKeyReq{
		key: id,
		res: res,
		err: errCh,
	}

	select {
	case pk := <-res:
		return pk, nil
	case err := <-errCh:
		return nil, fmt.Errorf("(Ledger/%s): %w", v.config.ID, err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// GetPublicKey returns a public key by given ID
func (v *Vault) GetPublicKey(ctx context.Context, id string) (vault.StoredKey, error) {
	key, err := parseKeyID(id)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("(Ledger/%s): %w", v.config.ID, err), http.StatusBadRequest)
	}
	return v.getPublicKey(ctx, key)
}

// ListPublicKeys returns a list of keys stored under the backend
func (v *Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	return &ledgerIterator{
		ctx: ctx,
		v:   v,
	}
}

func (v *Vault) SignMessage(ctx context.Context, digest []byte, key vault.StoredKey) (cryptoutils.Signature, error) {
	pk, ok := key.(*ledgerKey)
	if !ok {
		return nil, errors.Wrap(fmt.Errorf("(Ledger/%s): not a Ledger key: %T ", v.config.ID, key), http.StatusBadRequest)
	}

	res := make(chan cryptoutils.Signature, 1)
	errCh := make(chan error, 1)

	v.req <- &signReq{
		key:  pk.id,
		data: digest,
		sig:  res,
		err:  errCh,
	}

	select {
	case pk := <-res:
		return pk, nil
	case err := <-errCh:
		return nil, fmt.Errorf("(Ledger/%s): %w", v.config.ID, err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Name returns a backend name i.e. Ledger
func (v *Vault) Name() string {
	return "Ledger"
}

// VaultName returns an instance ID
func (v *Vault) VaultName() string {
	return v.config.ID
}

func (v *Vault) worker() {
	var (
		dev *tezosapp.App
		err error
		t   *time.Timer
		tch <-chan time.Time
	)

	closeAfter := v.config.CloseAfter
	if closeAfter == 0 {
		closeAfter = defaultCloseAfter
	}

	openDev := func(retry bool) error {
		if dev != nil {
			if retry {
				dev.Close()
			} else {
				return nil
			}
		}
		dev, err = deviceScanner.open(v.config.ID)
		if err != nil {
			return err
		}
		if t == nil {
			t = time.NewTimer(closeAfter)
		} else {
			if !t.Stop() {
				<-t.C
			}
			t.Reset(closeAfter)
		}
		tch = t.C
		return nil
	}

	for {
		select {
		case req := <-v.req:
			switch r := req.(type) {
			case *getKeyReq:
				if err = openDev(false); err != nil {
					r.err <- err
					break
				}
				pub, err := dev.GetPublicKey(r.key.dt, r.key.path, false)
				if err != nil {
					r.err <- err
					break
				}
				r.res <- &ledgerKey{
					pub: pub,
					id:  r.key,
				}

			case *signReq:
				// Retrying openDevice oncemore when ledger reset
				attempt := 0
				for attempt < 2 {
					if err = openDev(attempt == 1); err != nil {
						r.err <- err
						break
					}
					sig, err := dev.Sign(r.key.dt, r.key.path, r.data)
					if err != nil {
						if attempt == 1 {
							r.err <- err
						} else {
							attempt = attempt + 1
							continue
						}
						break
					}
					attempt = 3
					r.sig <- sig
				}
			}

		case <-tch:
			if err := dev.Close(); err != nil {
				log.Errorf("(Ledger/%s): %v", v.config.ID, err)
				break
			}
			dev = nil
			tch = nil
		}
	}
}

// New returns new Ledger signer
func New(ctx context.Context, conf *Config) (*Vault, error) {
	keys := make([]*keyID, len(conf.Keys))
	for i, k := range conf.Keys {
		kid, err := parseKeyID(k)
		if err != nil {
			return nil, err
		}
		keys[i] = kid
	}

	v := &Vault{
		config: *conf,
		keys:   keys,
		req:    make(chan devRequest, 10),
	}

	go v.worker()

	return v, nil
}

func parseKeyID(s string) (*keyID, error) {
	p := strings.SplitN(s, "/", 2)
	if len(p) != 2 {
		return nil, fmt.Errorf("error parsing key id: %s", s)
	}

	dt, err := tezosapp.DerivationTypeFromString(p[0])
	if err != nil {
		return nil, err
	}

	path := tezosapp.ParseBIP32(p[1])
	if path == nil {
		return nil, fmt.Errorf("error parsing key path: %s", p[1])
	}
	for _, p := range path {
		if p&tezosapp.BIP32H == 0 {
			return nil, errors.New("only hardened derivation is supported")
		}
	}
	if len(path) < 2 || path[0] != tezosapp.TezosBIP32Root[0] || path[1] != tezosapp.TezosBIP32Root[1] {
		path = append(tezosapp.TezosBIP32Root, path...)
	}
	if len(path) == 2 {
		return nil, errors.New("root key isn't allowed to use")
	}

	return &keyID{
		dt:   dt,
		path: path,
	}, nil
}

func (k *keyID) String() string {
	return k.dt.String() + "/" + k.path.String()
}

func init() {
	vault.RegisterVault("ledger", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
		var conf Config
		if node == nil || node.Kind == 0 {
			return nil, errors.New("(Ledger): config is missing")
		}
		if err := node.Decode(&conf); err != nil {
			return nil, err
		}

		if err := config.Validator().Struct(&conf); err != nil {
			return nil, err
		}

		return New(ctx, &conf)
	})

	vault.RegisterCommand(newLedgerCommand())
}
