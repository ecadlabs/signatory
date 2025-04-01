package watermark

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
	awskms "github.com/ecadlabs/signatory/pkg/vault/aws"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	readCapacityUnits  = 5
	writeCapacityUnits = 5
	defaultTable       = "watermark"
)

type AWSConfig struct {
	awskms.Config `yaml:",inline"`
	Table         string `yaml:"table"`
}

func (c *AWSConfig) table() string {
	if c.Table != "" {
		return c.Table
	}
	return defaultTable
}

type AWS struct {
	cfg    AWSConfig
	client *dynamodb.Client
}

func NewAWSWatermark(ctx context.Context, config *AWSConfig) (*AWS, error) {
	cfg, err := awskms.NewConfig(ctx, &config.Config)
	if err != nil {
		return nil, err
	}

	client := dynamodb.NewFromConfig(cfg)
	a := AWS{
		client: client,
		cfg:    *config,
	}
	if err := a.maybeCreateTable(ctx); err != nil {
		return nil, fmt.Errorf("(AWSWatermark) NewAWSWatermark: %w", err)
	}
	return &a, nil
}

func (a *AWS) maybeCreateTable(ctx context.Context) error {
	_, err := a.client.CreateTable(ctx, &dynamodb.CreateTableInput{
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("idx"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("request"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("idx"),
				KeyType:       types.KeyTypeHash,
			},
			{
				AttributeName: aws.String("request"),
				KeyType:       types.KeyTypeRange,
			},
		},
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(readCapacityUnits),
			WriteCapacityUnits: aws.Int64(writeCapacityUnits),
		},
		TableName: aws.String(a.cfg.table()),
	})
	if err != nil {
		var serr smithy.APIError
		if errors.As(err, &serr) && serr.ErrorCode() == "ResourceInUseException" {
			return nil
		}
		return err
	}
	log.WithField("table", a.cfg.table()).Info("table created")
	waiter := dynamodb.NewTableExistsWaiter(a.client)
	return waiter.Wait(context.TODO(), &dynamodb.DescribeTableInput{
		TableName: aws.String(a.cfg.table()),
	}, time.Minute*5) // give excess time
}

type watermark struct {
	Idx     string               `dynamodbav:"idx"`
	Request string               `dynamodbav:"request"`
	Level   int32                `dynamodbav:"lvl"`
	Round   int32                `dynamodbav:"round"`
	Digest  *tz.BlockPayloadHash `dynamodbav:"digest"`
}

func (w *watermark) key() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"idx":     &types.AttributeValueMemberS{Value: w.Idx},
		"request": &types.AttributeValueMemberS{Value: w.Request},
	}
}

func (w *watermark) watermark() *request.Watermark {
	return &request.Watermark{
		Level: w.Level,
		Round: w.Round,
		Hash:  tz.Some(*w.Digest),
	}
}

func (a *AWS) IsSafeToSign(ctx context.Context, pkh crypt.PublicKeyHash, req protocol.SignRequest, digest *crypt.Digest) error {
	m, ok := req.(request.WithWatermark)
	if !ok {
		log.WithFields(log.Fields{
			"pkh":  pkh.String(),
			"kind": req.SignRequestKind(),
		}).Debug("Watermark not required for this request type")
		return nil
	}
	wm := request.NewWatermark(m, digest)

	wmData := watermark{
		Idx:     strings.Join([]string{m.GetChainID().String(), pkh.String()}, "/"),
		Request: req.SignRequestKind(),
		Level:   wm.Level,
		Round:   wm.Round,
		Digest:  wm.Hash.UnwrapPtr(),
	}

	log.WithFields(log.Fields{
		"pkh":      pkh.String(),
		"chain_id": m.GetChainID().String(),
		"level":    wm.Level,
		"round":    wm.Round,
		"kind":     req.SignRequestKind(),
		"hash":     wm.Hash.UnwrapPtr(),
		"idx":      wmData.Idx,
	}).Debug("Starting watermark validation in DynamoDB")

	item, err := attributevalue.MarshalMap(&wmData)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"pkh":      pkh.String(),
			"chain_id": m.GetChainID().String(),
		}).Error("Failed to marshal watermark data")
		return fmt.Errorf("(AWSWatermark) IsSafeToSign: %w", err)
	}

	// First try to get the current watermark
	getItemInput := dynamodb.GetItemInput{
		TableName: aws.String(a.cfg.table()),
		Key: map[string]types.AttributeValue{
			"idx":     &types.AttributeValueMemberS{Value: wmData.Idx},
			"request": &types.AttributeValueMemberS{Value: wmData.Request},
		},
	}

	log.WithFields(log.Fields{
		"table":   a.cfg.table(),
		"idx":     wmData.Idx,
		"request": wmData.Request,
	}).Debug("Fetching current watermark from DynamoDB")

	result, err := a.client.GetItem(ctx, &getItemInput)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"table":   a.cfg.table(),
			"idx":     wmData.Idx,
			"request": wmData.Request,
		}).Error("Failed to get current watermark from DynamoDB")
		return fmt.Errorf("(AWSWatermark) IsSafeToSign: %w", err)
	}

	// If item exists, validate against it
	if result.Item != nil {
		var stored watermark
		if err := attributevalue.UnmarshalMap(result.Item, &stored); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"idx":     wmData.Idx,
				"request": wmData.Request,
			}).Error("Failed to unmarshal stored watermark")
			return fmt.Errorf("(AWSWatermark) IsSafeToSign: %w", err)
		}

		log.WithFields(log.Fields{
			"stored_level": stored.Level,
			"stored_round": stored.Round,
			"stored_hash":  stored.Digest,
			"new_level":    wm.Level,
			"new_round":    wm.Round,
			"new_hash":     wm.Hash.UnwrapPtr(),
			"idx":          wmData.Idx,
			"request":      wmData.Request,
		}).Debug("Comparing new watermark with stored watermark")

		// Validate the new watermark against stored one
		if wm.Level < stored.Level || (wm.Level == stored.Level && wm.Round <= stored.Round) {
			log.WithFields(log.Fields{
				"stored_level": stored.Level,
				"stored_round": stored.Round,
				"stored_hash":  stored.Digest,
				"new_level":    wm.Level,
				"new_round":    wm.Round,
				"new_hash":     wm.Hash.UnwrapPtr(),
				"idx":          wmData.Idx,
				"request":      wmData.Request,
				"reason":       "new watermark is not higher than stored watermark",
			}).Error("Watermark validation failed")
			return ErrWatermark
		}
		log.WithFields(log.Fields{
			"stored_level": stored.Level,
			"stored_round": stored.Round,
			"new_level":    wm.Level,
			"new_round":    wm.Round,
		}).Debug("Watermark validation passed - new watermark is higher")
	} else {
		log.WithFields(log.Fields{
			"idx":     wmData.Idx,
			"request": wmData.Request,
		}).Debug("No existing watermark found - proceeding with new watermark")
	}

	// If we get here, either no watermark exists or the new one is valid
	// Now try to write the new watermark
	putItemInput := dynamodb.PutItemInput{
		TableName: aws.String(a.cfg.table()),
		Item:      item,
	}

	log.WithFields(log.Fields{
		"table":   a.cfg.table(),
		"idx":     wmData.Idx,
		"request": wmData.Request,
		"level":   wm.Level,
		"round":   wm.Round,
	}).Debug("Writing new watermark to DynamoDB")

	_, err = a.client.PutItem(ctx, &putItemInput)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"table":   a.cfg.table(),
			"idx":     wmData.Idx,
			"request": wmData.Request,
		}).Error("Failed to write new watermark to DynamoDB")
		return fmt.Errorf("(AWSWatermark) IsSafeToSign: %w", err)
	}

	log.WithFields(log.Fields{
		"level":   wm.Level,
		"round":   wm.Round,
		"idx":     wmData.Idx,
		"request": wmData.Request,
		"hash":    wm.Hash.UnwrapPtr(),
	}).Debug("Watermark validation completed successfully and updated in DynamoDB")
	return nil
}

func init() {
	RegisterWatermark("aws", func(ctx context.Context, node *yaml.Node, global *config.Config) (Watermark, error) {
		var conf AWSConfig
		if node != nil {
			if err := node.Decode(&conf); err != nil {
				return nil, err
			}
		}
		return NewAWSWatermark(ctx, &conf)
	})
}
