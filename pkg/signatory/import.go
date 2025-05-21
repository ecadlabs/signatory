package signatory

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
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

func (s *Signatory) Generate(ctx context.Context, name string, keyType *cryptoutils.KeyType, n int) ([]*PublicKey, error) {
	v, ok := s.vaults[name]
	if !ok {
		return nil, fmt.Errorf("import: vault %s is not found", name)
	}
	generator, ok := v.(vault.Generator)
	if !ok {
		return nil, fmt.Errorf("import: vault %s doesn't support generate operation", name)
	}

	iter, err := generator.Generate(ctx, keyType, n)
	if err != nil {
		return nil, err
	}

	var keys []*PublicKey
keysLoop:
	for {
		key, err := iter.Next()
		if err != nil {
			switch {
			case errors.Is(err, vault.ErrDone):
				break keysLoop
			case errors.Is(err, vault.ErrKey):
				continue keysLoop
			default:
				return nil, err
			}
		}
		pkh := key.PublicKey().Hash()
		s.cache.push(&keyVaultPair{pkh: pkh, key: key})

		pol := s.fetchPolicyOrDefault(pkh)
		p := &PublicKey{
			KeyReference: key,
			Hash:         pkh,
			Policy:       pol,
			Active:       pol != nil,
		}
		keys = append(keys, p)
	}
	return keys, nil
}
