package confidentialspace

import (
	"context"
	"fmt"
	"iter"
	"slices"

	"cloud.google.com/go/firestore"
	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/signatory/pkg/utils/gcp"
	"google.golang.org/api/iterator"
)

const (
	defaultTable = "encrypted_keys"
)

type gcpStorageConfig struct {
	gcp.Config `yaml:",inline"`
	Project    string `yaml:"project" validate:"required"`
	Database   string `yaml:"database" validate:"required"`
	Collection string `yaml:"collection"`
}

func (c *gcpStorageConfig) collection() string {
	if c.Collection != "" {
		return c.Collection
	}
	return defaultTable
}

type gcpStorage struct {
	client *firestore.Client
	cfg    *gcpStorageConfig
	col    *firestore.CollectionRef
}

type gcpResult struct {
	err error
	out []*encryptedKey
}

type docItem struct {
	PKH   string `firestore:"pkh"`
	Value []byte `firestore:"value"`
}

func (r *gcpResult) Result() iter.Seq[*encryptedKey] { return slices.Values(r.out) }
func (r *gcpResult) Err() error                      { return r.err }

func newGCPStorage(ctx context.Context, config *gcpStorageConfig) (*gcpStorage, error) {
	opts, err := gcp.NewGCPOption(ctx, &config.Config)
	if err != nil {
		return nil, fmt.Errorf("(GCPStorage): %w", err)
	}

	var client *firestore.Client
	if config.Database == "" {
		client, err = firestore.NewClient(ctx, config.Project, opts...)
	} else {
		client, err = firestore.NewClientWithDatabase(ctx, config.Project, config.Database, opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("(GCPStorage): failed to create KMS client: %w", err)
	}

	return &gcpStorage{
		client: client,
		cfg:    config,
		col:    client.Collection(config.collection()),
	}, nil
}

func (g *gcpStorage) GetKeys(ctx context.Context) (result[*encryptedKey], error) {
	iter := g.col.Documents(ctx)
	keys := make([]*encryptedKey, 0)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break // No more documents
		}
		if err != nil {
			return nil, fmt.Errorf("(GCPStorage): %w", err)
		}
		var item docItem
		if err := doc.DataTo(&item); err != nil {
			return nil, fmt.Errorf("(GCPStorage): %w", err)
		}
		pkh, err := b58.ParsePublicKeyHash([]byte(item.PKH))
		if err != nil {
			return nil, fmt.Errorf("(GCPStorage): invalid public key hash %s: %w", item.PKH, err)
		}
		keys = append(keys, &encryptedKey{
			PublicKeyHash:       pkh,
			EncryptedPrivateKey: item.Value,
		})
	}
	return &gcpResult{out: keys}, nil
}

func (g *gcpStorage) ImportKey(ctx context.Context, encryptedKey *encryptedKey) error {
	_, err := g.col.Doc(encryptedKey.PublicKeyHash.String()).Set(ctx, &docItem{
		PKH:   encryptedKey.PublicKeyHash.String(),
		Value: encryptedKey.EncryptedPrivateKey,
	})
	return err
}
