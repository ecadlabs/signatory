package watermark

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
	awsutils "github.com/ecadlabs/signatory/pkg/utils/aws"
	"gopkg.in/yaml.v3"
)

const (
	readCapacityUnits  = 5
	writeCapacityUnits = 5
	defaultTable       = "watermark"
)

type AWSConfig struct {
	awsutils.Config `yaml:",inline"`
	Table           string `yaml:"table"`
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
	cfg, err := awsutils.NewAWSConfig(ctx, &config.Config)
	if err != nil {
		return nil, err
	}

	client := dynamodb.NewFromConfig(cfg)
	a := AWS{
		client: client,
		cfg:    *config,
	}
	if err := awsutils.DynamoDBMaybeCreateTable(ctx, client, a.makeCreateTableInput()); err != nil {
		return nil, fmt.Errorf("(AWSWatermark) NewAWSWatermark: %w", err)
	}
	return &a, nil
}

func (a *AWS) makeCreateTableInput() *dynamodb.CreateTableInput {
	return &dynamodb.CreateTableInput{
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
	}
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
		// watermark is not required
		return nil
	}
	wm := request.NewWatermark(m, digest)
	prev := watermark{
		Idx:     strings.Join([]string{m.GetChainID().String(), pkh.String()}, "/"),
		Request: req.SignRequestKind(),
	}
	for {
		response, err := a.client.GetItem(ctx, &dynamodb.GetItemInput{
			Key:       prev.key(),
			TableName: aws.String(a.cfg.table()),
		})
		if err != nil {
			return fmt.Errorf("(AWSWatermark) IsSafeToSign: %w", err)
		}

		update := watermark{
			Idx:     prev.Idx,
			Request: prev.Request,
			Level:   wm.Level,
			Round:   wm.Round,
			Digest:  wm.Hash.UnwrapPtr(),
		}
		item, err := attributevalue.MarshalMap(&update)
		if err != nil {
			return fmt.Errorf("(AWSWatermark) IsSafeToSign: %w", err)
		}
		input := dynamodb.PutItemInput{
			TableName: aws.String(a.cfg.table()),
			Item:      item,
		}

		if response.Item != nil {
			if err := attributevalue.UnmarshalMap(response.Item, &prev); err != nil {
				return fmt.Errorf("(AWSWatermark) IsSafeToSign: %w", err)
			}
			if !wm.Validate(prev.watermark()) {
				return ErrWatermark
			}
			input.ConditionExpression = aws.String("lvl = :lvl AND round = :round AND digest = :digest")
			input.ExpressionAttributeValues = map[string]types.AttributeValue{
				":lvl":    response.Item["lvl"],
				":round":  response.Item["round"],
				":digest": response.Item["digest"],
			}
		} else {
			input.ConditionExpression = aws.String("attribute_not_exists(idx)")
		}

		_, err = a.client.PutItem((ctx), &input)
		var serr smithy.APIError
		if err == nil {
			return nil
		} else if !errors.As(err, &serr) || serr.ErrorCode() != "ConditionalCheckFailedException" {
			return fmt.Errorf("(AWSWatermark) IsSafeToSign: %w", err)
		}
		// retry
	}
}

func init() {
	RegisterWatermark("aws", func(ctx context.Context, node *yaml.Node, global config.GlobalContext) (Watermark, error) {
		var conf AWSConfig
		if node != nil {
			if err := node.Decode(&conf); err != nil {
				return nil, err
			}
		}
		return NewAWSWatermark(ctx, &conf)
	})
}
