package signatory

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"

	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	log "github.com/sirupsen/logrus"
)

// Import a keyPair inside the vault
func (s *Signatory) Import(ctx context.Context, importerName string, secretKey []byte, passCB func() ([]byte, error), opt utils.Options) (*PublicKey, error) {
	v, ok := s.vaults[importerName]
	if !ok {
		return nil, fmt.Errorf("import: vault %s is not found", importerName)
	}

	importer, ok := v.(vault.Importer)
	if !ok {
		return nil, fmt.Errorf("import: vault %s doesn't support import operation", importerName)
	}

	var priv crypt.PrivateKey
	if bytes.HasPrefix(secretKey, []byte("-----BEGIN PRIVATE KEY-----")) {
		block, _ := pem.Decode(secretKey)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		var err error
		if priv, err = cryptoutils.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	} else {
		maybeEncrypted, err := b58.ParseEncryptedPrivateKey(secretKey)
		if err != nil {
			return nil, err
		}
		decrypted, err := maybeEncrypted.Decrypt(passCB)
		if err != nil {
			return nil, err
		}
		if priv, err = crypt.NewPrivateKey(decrypted); err != nil {
			return nil, err
		}
	}
	pub := priv.Public()
	hash := pub.Hash()
	l := s.logger().WithFields(log.Fields{
		logPKH:   hash,
		logVault: importer.Name(),
	})
	l.Info("Requesting import operation")

	ref, err := importer.Import(ctx, priv, opt)
	if err != nil {
		return nil, err
	}

	s.cache.push(&keyVaultPair{pkh: hash, key: ref})

	l.WithField(logPKH, hash).Info("Successfully imported")
	pol := s.fetchPolicyOrDefault(hash)
	return &PublicKey{
		KeyReference: ref,
		Hash:         hash,
		Policy:       s.fetchPolicyOrDefault(hash),
		Active:       pol != nil,
	}, nil
}
