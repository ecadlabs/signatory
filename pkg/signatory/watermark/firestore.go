package watermark

import (
	"context"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol/core" // Import config directly
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	"cloud.google.com/go/firestore"
)

const (
	defaultCollection = "watermark"
)

type FirestoreConfig struct {
	CredentialsFile string `yaml:"file"`
	Database        string `yaml:"database"`
	ProjectID       string `yaml:"project_id"`
	Collection      string `yaml:"collection"`
}

func (c *FirestoreConfig) collection() string {
	if c.Collection != "" {
		return c.Collection
	}
	return defaultCollection
}

type Firestore struct {
	client *firestore.Client
	col    *firestore.CollectionRef
}

func NewFirestoreWatermark(ctx context.Context, config *FirestoreConfig) (*Firestore, error) {
	var client *firestore.Client
	var err error

	if config.Database != "" {
		client, err = firestore.NewClientWithDatabase(ctx, config.ProjectID, config.Database, option.WithCredentialsFile(config.CredentialsFile))
	} else {
		client, err = firestore.NewClient(ctx, config.ProjectID, option.WithCredentialsFile(config.CredentialsFile))
	}

	if err != nil {
		return nil, err
	}

	col := client.Collection(config.collection())

	inst := Firestore{
		client: client,
		col:    col,
	}

	return &inst, nil
}

type FirestoreWatermark struct {
	Request string               `firestore:"request"`
	Level   int32                `firestore:"lvl"`
	Round   int32                `firestore:"round"`
	Digest  *tz.BlockPayloadHash `firestore:"digest"`
}

func (f *Firestore) IsSafeToSign(ctx context.Context, pkh crypt.PublicKeyHash, req core.SignRequest, digest *crypt.Digest) error {
	m, ok := req.(request.WithWatermark)
	if !ok {
		// watermark is not required
		return nil
	}

	docRef := f.col.Doc(m.GetChainID().String()).Collection(req.SignRequestKind()).Doc(pkh.String())

	wm := request.NewWatermark(m, digest)

	newWm := FirestoreWatermark{
		Request: req.SignRequestKind(),
		Level:   wm.Level,
		Round:   wm.Round,
		Digest:  wm.Hash.UnwrapPtr(),
	}

	return f.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		docSnap, err := tx.Get(docRef) // Read document

		errCode := status.Code(err)
		if errCode != codes.NotFound && errCode != codes.OK {
			return err
		}

		if err == nil { // watermark exists
			var oldWm FirestoreWatermark
			err := docSnap.DataTo(&oldWm)
			if err != nil {
				return err
			}

			if oldWm.Level >= newWm.Level && (oldWm.Level != newWm.Level || oldWm.Round >= newWm.Round) {
				return ErrWatermark
			}
		}

		tx.Set(docRef, newWm)
		return nil
	})
}

func init() {
	RegisterWatermark("firestore", func(ctx context.Context, node *yaml.Node, global *config.Config) (Watermark, error) {
		var config FirestoreConfig
		if node != nil {
			if err := node.Decode(&config); err != nil {
				return nil, err
			}
		}
		return NewFirestoreWatermark(ctx, &config)
	})
}
