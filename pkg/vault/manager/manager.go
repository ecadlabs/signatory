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
var ErrVaultNotFound = errors.Wrap(stderr.New("the key is not found in any vault"), http.StatusNotFound)

type Signer interface {
	GetPublicKey(ctx context.Context, keyHash crypt.PublicKeyHash) (*PublicKey, error)
	SignBytes(ctx context.Context, pkh crypt.PublicKeyHash, message []byte) (crypt.Signature, error)
}

type keyVaultPair struct {
	pkh      crypt.PublicKeyHash
	key      vault.StoredKey
	vault    vault.Vault
	instName string
}

func (k *keyVaultPair) instanceName() string {
	if n, ok := k.vault.(vault.VaultNamer); ok {
		return n.VaultName()
	}
	return k.instName
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
	crypt.PublicKey
	VaultName         string
	VaultInstanceName string
	ID                string
}

type ManagerConfig struct {
	Vaults       map[string]*config.VaultConfig
	Logger       log.FieldLogger
	VaultFactory vault.Factory
}

func (c *ManagerConfig) GetVaults() map[string]*config.VaultConfig { return c.Vaults }
func (c *ManagerConfig) GetLogger() log.FieldLogger                { return c.Logger }
func (c *ManagerConfig) GetVaultFactory() vault.Factory            { return c.VaultFactory }

type Config interface {
	GetVaults() map[string]*config.VaultConfig
	GetLogger() log.FieldLogger
	GetVaultFactory() vault.Factory
}

type Manager struct {
	config Config
	vaults map[string]vault.Vault
	cache  keyCache
}

func (m *Manager) logger() log.FieldLogger {
	if l := m.config.GetLogger(); l != nil {
		return l
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
			p := &keyVaultPair{pkh: pkh, key: key, vault: v, instName: name}
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
			PublicKey:         pk,
			VaultName:         p.vault.Name(),
			VaultInstanceName: p.instanceName(),
			ID:                p.key.ID(),
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
		PublicKey:         p.key.PublicKey(),
		VaultName:         p.vault.Name(),
		VaultInstanceName: p.instanceName(),
		ID:                p.key.ID(),
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

	var instanceName string
	if n, ok := importer.(vault.VaultNamer); ok {
		instanceName = n.VaultName()
	} else {
		instanceName = importerName
	}
	l = l.WithField(logVaultName, instanceName)

	l.Info("Requesting import operation")

	stored, err := importer.Import(ctx, priv, opt)
	if err != nil {
		return nil, err
	}

	m.cache.push(&keyVaultPair{pkh: hash, key: stored, vault: importer})

	l.WithField(logKeyID, stored.ID()).Info("Successfully imported")
	return &PublicKey{
		PublicKey:         pub,
		VaultName:         importer.Name(),
		VaultInstanceName: instanceName,
		ID:                stored.ID(),
	}, nil
}

func (m *Manager) SignBytes(ctx context.Context, pkh crypt.PublicKeyHash, message []byte) (crypt.Signature, error) {
	l := m.logger().WithField(logPKH, pkh)
	p, err := m.getPublicKey(ctx, pkh)
	if err != nil {
		l.Error(err)
		return nil, err
	}

	l = l.WithFields(log.Fields{logVault: p.vault.Name(), logVaultName: p.instanceName()})

	l.Info("Requesting signing operation")
	sig, err := p.vault.SignMessage(ctx, message, p.key)
	if err != nil {
		return nil, err
	}
	l.WithField("raw", sig).Debug("Signed bytes")
	l.Debugf("Encoded signature: %v", sig)

	return sig, nil
}

// New returns Manager instance
func New(ctx context.Context, c Config) (*Manager, error) {
	m := &Manager{
		config: c,
		vaults: make(map[string]vault.Vault, len(c.GetVaults())),
	}

	factory := c.GetVaultFactory()
	if factory == nil {
		factory = vault.Registry()
	}

	// Initialize vaults
	for name, vc := range c.GetVaults() {
		if vc == nil {
			continue
		}
		l := m.logger().WithFields(log.Fields{
			logVault:     vc.Driver,
			logVaultName: name,
		})
		l.Infof("Initializing vault %s", vc.Driver)
		v, err := factory.New(ctx, vc.Driver, &vc.Config)
		if err != nil {
			return nil, err
		}
		m.vaults[name] = v
	}

	return m, nil
}

// Ready returns true if all backends are ready
func (m *Manager) Ready(ctx context.Context) (bool, error) {
	for _, v := range m.vaults {
		if rc, ok := v.(vault.ReadinessChecker); ok {
			if ok, err := rc.Ready(ctx); !ok || err != nil {
				return ok, err
			}
		}
	}
	return true, nil
}

var _ Signer = (*Manager)(nil)
