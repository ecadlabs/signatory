package watermark

import (
	"context"
	"fmt"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol/core" // Import config directly
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/metrics"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
	"github.com/ecadlabs/signatory/pkg/utils/gcp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	"cloud.google.com/go/firestore"
)

const (
	defaultCollection = "watermark"
)

type GCPConfig struct {
	gcp.Config `yaml:",inline"`
	Project    string `yaml:"project" validate:"required"`
	Database   string `yaml:"database" validate:"required"`
	Collection string `yaml:"collection"`
}

func (c *GCPConfig) collection() string {
	if c.Collection != "" {
		return c.Collection
	}
	return defaultCollection
}

type GCP struct {
	client  *firestore.Client
	col     *firestore.CollectionRef
	colName string
}

func NewGCPWatermark(ctx context.Context, config *GCPConfig) (*GCP, error) {
	var client *firestore.Client
	var err error

	opts, err := gcp.NewGCPOption(ctx, &config.Config)
	if err != nil {
		return nil, fmt.Errorf("(GCPWatermark) NewGCPWatermark: %w", err)
	}

	if config.Database == "" {
		client, err = firestore.NewClient(ctx, config.Project, opts...)
	} else {
		client, err = firestore.NewClientWithDatabase(ctx, config.Project, config.Database, opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("(GCPWatermark) NewGCPWatermark: %w", err)
	}

	colName := config.collection()
	col := client.Collection(colName)

	inst := GCP{
		client:  client,
		col:     col,
		colName: colName,
	}

	return &inst, nil
}

type GCPWatermark struct {
	Request string               `firestore:"request"`
	Level   int32                `firestore:"lvl"`
	Round   int32                `firestore:"round"`
	Digest  *tz.BlockPayloadHash `firestore:"digest"`
}

func (f *GCP) IsSafeToSign(ctx context.Context, pkh crypt.PublicKeyHash, req core.SignRequest, digest *crypt.Digest) error {
	m, ok := req.(request.WithWatermark)
	if !ok {
		// watermark is not required
		return nil
	}

	docRef := f.col.Doc(m.GetChainID().String()).Collection(req.SignRequestKind()).Doc(pkh.String())

	wm := request.NewWatermark(m, digest)

	newWm := GCPWatermark{
		Request: req.SignRequestKind(),
		Level:   wm.Level,
		Round:   wm.Round,
		Digest:  wm.Hash.UnwrapPtr(),
	}

	opts := metrics.IOInterceptorOptions[bool]{
		Backend:   "gcp",
		Operation: "write",
		TableName: f.colName,
		TargetFunc: func() (bool, error) {
			err := f.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
				docSnap, err := tx.Get(docRef) // Read document

				if err != nil {
					if status.Code(err) == codes.NotFound {
						// Document doesn't exist, safe to create
						tx.Set(docRef, newWm)
						return nil
					}
					metrics.RecordIOError("gcp", status.Code(err).String(), f.colName, "write")
					return fmt.Errorf("(GCPWatermark) IsSafeToSign: %w", err)
				}

				// Document exists, check watermark
				var oldWm GCPWatermark
				if err := docSnap.DataTo(&oldWm); err != nil {
					metrics.RecordIOError("gcp", "decode_error", f.colName, "write")
					return fmt.Errorf("(GCPWatermark) IsSafeToSign: %w", err)
				}

				if oldWm.Level >= newWm.Level && (oldWm.Level != newWm.Level || oldWm.Round >= newWm.Round) {
					return ErrWatermark
				}

				tx.Set(docRef, newWm)
				return nil
			})
			return err == nil, err
		},
	}
	_, err := metrics.IOInterceptor(&opts)
	return err
}

func init() {
	RegisterWatermark("gcp", func(ctx context.Context, node *yaml.Node, global config.GlobalContext) (watermarkImpl, error) {
		var config GCPConfig
		if node != nil {
			if err := node.Decode(&config); err != nil {
				return nil, err
			}
		}
		return NewGCPWatermark(ctx, &config)
	})
}
