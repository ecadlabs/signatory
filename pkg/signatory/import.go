package signatory

import (
	"context"
	"crypto"

	"github.com/ecadlabs/signatory/pkg/tezos"
	log "github.com/sirupsen/logrus"
)

// Importer interface representing an importer backend
type Importer interface {
	Import(ctx context.Context, pk crypto.PrivateKey) (string, error)
	Name() string
}

// ImportedKey struct containing information about an imported key
type ImportedKey struct {
	Hash  string
	KeyID string
}

// Import a keyPair inside the vault
func (s *Signatory) Import(secretKey string, importer Importer) (*ImportedKey, error) {
	pk, err := tezos.ParseTezosPrivateKey()
	if err != nil {
		return nil, err
	}

	hash, err := keyPair.PubKeyHash()
	if err != nil {
		return nil, err
	}

	logfields := log.Fields{
		LogPKH:   hash,
		LogVault: importer.Name(),
	}
	if n, ok := importer.(VaultNamer); ok {
		logfields[LogVaultName] = n.VaultName()
	}
	l := s.logger.WithFields(logfields)

	l.Info("Requesting import operation")

	keyID, err := importer.Import(context.TODO(), jwk)
	if err != nil {
		return nil, err
	}

	l.WithField(LogKeyID, keyID).Info("Successfully imported")

	importedKey := &ImportedKey{
		KeyID: keyID,
		Hash:  hash,
	}

	return importedKey, nil
}
