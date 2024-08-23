//go:build darwin

package secureenclave

import (
	"context"
	"crypto/x509"
	"encoding/json"
	stderr "errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/secureenclave/cryptokit"
	"gopkg.in/yaml.v3"
)

type storageEntry struct {
	ID    string `json:"id,omitempty"`
	Value []byte `json:"value"`
}

type cryptoKitKey struct {
	id   string
	priv *cryptokit.PrivateKey
	pub  crypt.PublicKey
}

func (priv *cryptoKitKey) PublicKey() crypt.PublicKey {
	return priv.pub
}

func (priv *cryptoKitKey) ID() string {
	return priv.id
}

type parsedKeys struct {
	keys  []*cryptoKitKey
	index map[string]*cryptoKitKey
}

type Vault struct {
	keys *parsedKeys
}

// Name returns backend name
func (v *Vault) Name() string { return "SecureEnclave" }

func loadKeys(file string) (*parsedKeys, error) {
	keys := &parsedKeys{
		index: make(map[string]*cryptoKitKey),
	}
	buf, err := os.ReadFile(file)
	if err != nil {
		if stderr.Is(err, os.ErrNotExist) {
			return keys, nil
		}
		return nil, err
	}
	var storage []*storageEntry
	if err := json.Unmarshal(buf, &storage); err != nil {
		return nil, err
	}
	for _, e := range storage {
		priv, err := cryptokit.NewPrivateKeyFromData(e.Value)
		if err != nil {
			return nil, err
		}
		p, err := x509.ParsePKIXPublicKey(priv.Public().DERBytes()) // cryptoutils wrapper is not needed here because SE supports P256 curve only
		if err != nil {
			return nil, err
		}
		pub, err := crypt.NewPublicKeyFrom(p)
		if err != nil {
			return nil, err
		}

		id := e.ID
		if id == "" {
			id = pub.Hash().String()
		}
		if _, ok := keys.index[id]; ok {
			return nil, fmt.Errorf("key id `%s' is already in use", e.ID)
		}

		entry := &cryptoKitKey{
			id:   id,
			priv: priv,
			pub:  pub,
		}
		keys.keys = append(keys.keys, entry)
		keys.index[e.ID] = entry
	}
	return keys, nil
}

// GetPublicKey retrieve a public key
func (v *Vault) GetPublicKey(ctx context.Context, keyID string) (vault.StoredKey, error) {
	key, ok := v.keys.index[keyID]
	if !ok {
		return nil, errors.Wrap(fmt.Errorf("(SecureEnclave): key not found in vault: %s", keyID), http.StatusNotFound)
	}
	return key, nil
}

// ListPublicKeys list all public key available on disk
func (v *Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	return &iterator{keys: v.keys.keys}
}

// Sign sign using the specified key
func (v *Vault) SignMessage(ctx context.Context, message []byte, k vault.StoredKey) (sig crypt.Signature, err error) {
	key, ok := k.(*cryptoKitKey)
	if !ok {
		return nil, errors.Wrap(fmt.Errorf("(SecureEnclave): invalid key type: %T ", k), http.StatusBadRequest)
	}
	digest := crypt.DigestFunc(message)
	s, err := key.priv.Signature((*[32]byte)(&digest))
	if err != nil {
		return nil, fmt.Errorf("(SecureEnclave): %w", err)
	}
	return crypt.NewSignatureFromBytes(s.DERBytes(), key.pub)
}

type iterator struct {
	keys []*cryptoKitKey
	idx  int
}

func (i *iterator) Next() (key vault.StoredKey, err error) {
	if i.idx == len(i.keys) {
		return nil, vault.ErrDone
	}
	key = i.keys[i.idx]
	i.idx++
	return key, nil
}

const defaultKeysFile = "secure_enclave_keys"

func init() {
	if !cryptokit.IsAvailable() {
		return
	}
	vault.RegisterVault("secure_enclave", func(ctx context.Context, node *yaml.Node, g config.GlobalContext) (vault.Vault, error) {
		name := filepath.Join(g.BaseDir(), defaultKeysFile)
		keys, err := loadKeys(name)
		if err != nil {
			return nil, fmt.Errorf("(SecureEnclave): %w", err)
		}
		return &Vault{keys: keys}, nil
	})
	vault.RegisterCommand(newSecureEnclaveCommand)
}
