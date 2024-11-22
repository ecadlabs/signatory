package signatory

import (
	"context"
	"fmt"

	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	log "github.com/sirupsen/logrus"
)

// Import a keyPair inside the vault
func (s *Signatory) Import(ctx context.Context, importerName string, secretKey string, passCB func() ([]byte, error), opt utils.Options) (*PublicKey, error) {
	v, ok := s.vaults[importerName]
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
	l := s.logger().WithFields(log.Fields{
		logPKH:   hash,
		logVault: importer.Name(),
	})
	l.Info("Requesting import operation")

	stored, err := importer.Import(ctx, priv, opt)
	if err != nil {
		return nil, err
	}

	s.cache.push(&keyVaultPair{pkh: hash, key: stored})

	l.WithField(logPKH, hash).Info("Successfully imported")
	return &PublicKey{
		PublicKey:     pub,
		PublicKeyHash: hash,
		VaultName:     importer.Name(),
		Policy:        s.fetchPolicyOrDefault(hash),
	}, nil
}
