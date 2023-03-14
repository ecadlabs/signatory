package signatory

import (
	"context"
	"fmt"

	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/gotez/b58"
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
	priv, err := decrypted.PrivateKey()
	if err != nil {
		return nil, err
	}
	pub, err := tz.NewPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}

	hash := pub.Hash().String()
	l := s.logger().WithFields(log.Fields{
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

	s.cache.push(hash, &keyVaultPair{key: stored, vault: importer})

	l.WithField(logKeyID, stored.ID()).Info("Successfully imported")
	return &PublicKey{
		PublicKey:     pub.String(),
		PublicKeyHash: hash,
		VaultName:     importer.Name(),
		ID:            stored.ID(),
		Policy:        s.fetchPolicyOrDefault(hash),
	}, nil
}
