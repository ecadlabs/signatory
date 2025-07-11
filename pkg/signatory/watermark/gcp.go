package watermark

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

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

type GCPConfig struct {
	CredentialsFile string `yaml:"file"`
	Database        string `yaml:"database"`
	ProjectID       string `yaml:"project_id"`
	Collection      string `yaml:"collection"`
}

type GCPCredentials struct {
	ProjectID string `json:"project_id"`
}

func extractProjectIDFromCredentials(credentialsFile string) (string, error) {
	// reads the GCP credentials file and extracts the project_id
	if credentialsFile == "" {
		return "", fmt.Errorf("credentials file path is empty")
	}

	data, err := os.ReadFile(credentialsFile)
	if err != nil {
		return "", fmt.Errorf("failed to read credentials file: %w", err)
	}

	var creds GCPCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return "", fmt.Errorf("failed to parse credentials JSON: %w", err)
	}

	if creds.ProjectID == "" {
		return "", fmt.Errorf("project_id not found in credentials file")
	}

	return creds.ProjectID, nil
}

func (c *GCPConfig) collection() string {
	if c.Collection != "" {
		return c.Collection
	}
	return defaultCollection
}

type GCP struct {
	client *firestore.Client
	col    *firestore.CollectionRef
}

func NewGCPWatermark(ctx context.Context, config *GCPConfig) (*GCP, error) {
	var client *firestore.Client
	var err error

	projectID := config.ProjectID
	if projectID == "" {
		// Try to extract project ID from credentials file
		projectID, err = extractProjectIDFromCredentials(config.CredentialsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get project ID from credentials file: %w", err)
		}
	}

	if config.Database != "" {
		client, err = firestore.NewClientWithDatabase(ctx, projectID, config.Database, option.WithCredentialsFile(config.CredentialsFile))
	} else {
		client, err = firestore.NewClient(ctx, projectID, option.WithCredentialsFile(config.CredentialsFile))
	}

	if err != nil {
		return nil, err
	}

	col := client.Collection(config.collection())

	inst := GCP{
		client: client,
		col:    col,
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

	return f.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		docSnap, err := tx.Get(docRef) // Read document

		errCode := status.Code(err)
		if errCode != codes.NotFound && errCode != codes.OK {
			return err
		}

		if err == nil { // watermark exists
			var oldWm GCPWatermark
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
	RegisterWatermark("gcp", func(ctx context.Context, node *yaml.Node, global *config.Config) (Watermark, error) {
		var config GCPConfig
		if node != nil {
			if err := node.Decode(&config); err != nil {
				return nil, err
			}
		}
		return NewGCPWatermark(ctx, &config)
	})
}
