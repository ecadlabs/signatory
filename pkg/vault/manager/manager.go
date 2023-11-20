package manager

import (
	"context"
	stderr "errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/ecadlabs/gotez/b58"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	log "github.com/sirupsen/logrus"
)

const (
	logPKH       = "pkh"
	logVault     = "vault"
	logVaultName = "vault_name"
	logKeyID     = "key_id"
	logClient    = "client_pkh"
	logRaw       = "raw"
)

// ErrVaultNotFound error return when a vault is not found
var ErrVaultNotFound = errors.Wrap(stderr.New("this key not found in any vault"), http.StatusNotFound)

type keyVaultPair struct {
	pkh   crypt.PublicKeyHash
	key   vault.StoredKey
	vault vault.Vault
	name  string
}

type keyCache struct {
	cache hashmap.PublicKeyHashMap[*keyVaultPair]
	mtx   sync.Mutex
}

func (k *keyCache) push(pair *keyVaultPair) {
	k.mtx.Lock()
	defer k.mtx.Unlock()

	if k.cache == nil {
		k.cache = make(hashmap.PublicKeyHashMap[*keyVaultPair])
	}
	k.cache.Insert(pair.pkh, pair)
}

func (k *keyCache) get(pkh crypt.PublicKeyHash) *keyVaultPair {
	k.mtx.Lock()
	defer k.mtx.Unlock()

	if pair, ok := k.cache.Get(pkh); ok {
		return pair
	}

	return nil
}

func (k *keyCache) drop() {
	k.mtx.Lock()
	defer k.mtx.Unlock()
	k.cache = nil
}

// PublicKey contains public key with its hash
type PublicKey struct {
	PublicKey     crypt.PublicKey
	PublicKeyHash crypt.PublicKeyHash
	VaultName     string
	ID            string
}

// Config represents Signatory configuration
type Config struct {
	Vaults       map[string]*config.VaultConfig
	Logger       log.FieldLogger
	VaultFactory vault.Factory
}

type Manager struct {
	config Config
	vaults map[string]vault.Vault
	cache  keyCache
}

func (m *Manager) logger() log.FieldLogger {
	if m.config.Logger != nil {
		return m.config.Logger
	}
	return log.StandardLogger()
}

type publicKeys = hashmap.PublicKeyHashMap[*keyVaultPair]

func (m *Manager) listPublicKeys(ctx context.Context) (ret publicKeys, list []*keyVaultPair, err error) {
	ret = make(publicKeys)
	for name, v := range m.vaults {
		var vaultKeys []*keyVaultPair
		iter := v.ListPublicKeys(ctx)
	keys:
		for {
			key, err := iter.Next()
			if err != nil {
				switch {
				case stderr.Is(err, vault.ErrDone):
					break keys
				case stderr.Is(err, vault.ErrKey):
					continue keys
				default:
					return nil, nil, err
				}
			}
			pkh := key.PublicKey().Hash()
			p := &keyVaultPair{pkh: pkh, key: key, vault: v, name: name}
			m.cache.push(p)

			ret.Insert(pkh, p)
			vaultKeys = append(vaultKeys, p)
		}
		if len(vaultKeys) == 0 {
			m.logger().Error("No valid keys found in the vault ", name)
		}
		list = append(list, vaultKeys...)
	}
	return ret, list, nil
}

// ListPublicKeys retrieve the list of all public keys supported by the current configuration
func (m *Manager) ListPublicKeys(ctx context.Context) ([]*PublicKey, error) {
	_, list, err := m.listPublicKeys(ctx)
	if err != nil {
		return nil, err
	}

	ret := make([]*PublicKey, len(list))
	for i, p := range list {
		pk := p.key.PublicKey()
		ret[i] = &PublicKey{
			PublicKey:     pk,
			PublicKeyHash: p.pkh,
			VaultName:     p.vault.Name(),
			ID:            p.key.ID(),
		}
	}
	return ret, nil
}

func (m *Manager) getPublicKey(ctx context.Context, keyHash crypt.PublicKeyHash) (*keyVaultPair, error) {
	cached := m.cache.get(keyHash)
	if cached != nil {
		return cached, nil
	}

	m.logger().WithField(logPKH, keyHash).Debugf("Fetching public key for: %s", keyHash)

	keys, _, err := m.listPublicKeys(ctx)
	if err != nil {
		return nil, err
	}

	if p, ok := keys.Get(keyHash); ok {
		return p, nil
	}
	return nil, ErrVaultNotFound
}

// GetPublicKey retrieve the public key from a vault
func (m *Manager) GetPublicKey(ctx context.Context, keyHash crypt.PublicKeyHash) (*PublicKey, error) {
	p, err := m.getPublicKey(ctx, keyHash)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		PublicKey:     p.key.PublicKey(),
		PublicKeyHash: keyHash,
		VaultName:     p.vault.Name(),
		ID:            p.key.ID(),
	}, nil
}

// Unlock unlock all the vaults
func (m *Manager) Unlock(ctx context.Context) error {
	for _, v := range m.vaults {
		if unlocker, ok := v.(vault.Unlocker); ok {
			if err := unlocker.Unlock(ctx); err != nil {
				return err
			}
		}
	}
	m.cache.drop()
	return nil
}

// Import a keyPair inside the vault
func (m *Manager) Import(ctx context.Context, importerName string, secretKey string, passCB func() ([]byte, error), opt utils.Options) (*PublicKey, error) {
	v, ok := m.vaults[importerName]
	if !ok {
		return nil, fmt.Errorf("import: vault %s is not found", importerName)
	}

	importer, ok := v.(vault.Importer)
	if !ok {
		return nil, fmt.Errorf("import: vault %s doesn't support import operation", importerName)
	}

	maybeEncrypted, err := b58.ParseEncryptedPrivateKey([]byte(secretKey))
	if err != nil {
		return nil, err
	}
	decrypted, err := maybeEncrypted.Decrypt(passCB)
	if err != nil {
		return nil, err
	}
	priv, err := crypt.NewPrivateKey(decrypted)
	if err != nil {
		return nil, err
	}
	pub := priv.Public()
	hash := pub.Hash()
	l := m.logger().WithFields(log.Fields{
		logPKH:   hash,
		logVault: importer.Name(),
	})
	if n, ok := importer.(vault.VaultNamer); ok {
		l = l.WithField(logVaultName, n.VaultName())
	} else {
		l = l.WithField(logVaultName, importerName)
	}

	l.Info("Requesting import operation")

	stored, err := importer.Import(ctx, priv, opt)
	if err != nil {
		return nil, err
	}

	m.cache.push(&keyVaultPair{pkh: hash, key: stored, vault: importer})

	l.WithField(logKeyID, stored.ID()).Info("Successfully imported")
	return &PublicKey{
		PublicKey:     pub,
		PublicKeyHash: hash,
		VaultName:     importer.Name(),
		ID:            stored.ID(),
	}, nil
}

type SignRequest struct {
	PublicKeyHash crypt.PublicKeyHash
	Message       []byte
}

func (m *Manager) SignData(ctx context.Context, req *SignRequest) (crypt.Signature, error) {
	l := m.logger().WithField(logPKH, req.PublicKeyHash)
	p, err := m.getPublicKey(ctx, req.PublicKeyHash)
	if err != nil {
		l.Error(err)
		return nil, err
	}

	l = l.WithField(logVault, p.vault.Name())
	if n, ok := p.vault.(vault.VaultNamer); ok {
		l = l.WithField(logVaultName, n.VaultName())
	} else {
		l = l.WithField(logVaultName, p.name)
	}

	l.Info("Requesting signing operation")
	sig, err := p.vault.SignMessage(ctx, req.Message, p.key)
	if err != nil {
		return nil, err
	}
	l.WithField("raw", sig).Debug("Signed bytes")
	l.Debugf("Encoded signature: %v", sig)

	return sig, nil
}
