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
	"github.com/ecadlabs/gotez/v2/protocol/core"
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
			log.Infof("DynamoDB watermark backend using existing table '%s'", a.cfg.table())
			return nil
		}
		return err
	}
	log.Infof("DynamoDB watermark backend created table '%s'", a.cfg.table())
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

func (a *AWS) IsSafeToSign(ctx context.Context, pkh crypt.PublicKeyHash, req core.SignRequest, digest *crypt.Digest) error {
	m, ok := req.(request.WithWatermark)
	if !ok {
		// watermark is not required
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
	item, err := attributevalue.MarshalMap(&wmData)
	if err != nil {
		return fmt.Errorf("(AWSWatermark) IsSafeToSign: %w", err)
	}
	putItemInput := dynamodb.PutItemInput{
		TableName:           aws.String(a.cfg.table()),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(idx) or lvl < :new_lvl or (lvl = :new_lvl and round < :new_round)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":new_lvl":   item["lvl"],
			":new_round": item["round"],
		},
	}
	_, err = a.client.PutItem((ctx), &putItemInput)
	if err != nil {
		log.Error(err)
		return ErrWatermark
	}
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
