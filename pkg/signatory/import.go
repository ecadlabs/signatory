package signatory

import (
	"context"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/tezos"
	log "github.com/sirupsen/logrus"
)

// Importer interface representing an importer backend
type Importer interface {
	Vault
	Import(ctx context.Context, pk cryptoutils.PrivateKey) (StoredKey, error)
}

// Import a keyPair inside the vault
func (s *Signatory) Import(ctx context.Context, importer Importer, secretKey string, passCB tezos.PassphraseFunc) (*PublicKey, error) {
	pk, err := tezos.ParsePrivateKey(secretKey, passCB)
	if err != nil {
		return nil, err
	}

	pub := pk.Public()

	hash, err := tezos.EncodePublicKeyHash(pub)
	if err != nil {
		return nil, err
	}

	l := s.logger().WithFields(log.Fields{
		LogPKH:   hash,
		LogVault: importer.Name(),
	})
	if n, ok := importer.(VaultNamer); ok {
		l = l.WithField(LogVaultName, n.VaultName())
	}

	l.Info("Requesting import operation")

	stored, err := importer.Import(ctx, pk)
	if err != nil {
		return nil, err
	}

	s.cache.push(hash, &keyVaultPair{key: stored, vault: importer})

	l.WithField(LogKeyID, stored.ID()).Info("Successfully imported")

	enc, err := tezos.EncodePublicKey(pub)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		PublicKey:     enc,
		PublicKeyHash: hash,
		VaultName:     importer.Name(),
		ID:            stored.ID(),
	}, nil
}
