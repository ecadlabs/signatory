package nitro

import (
	"context"
	"iter"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/ecadlabs/gotez/v2/b58"
	awsutils "github.com/ecadlabs/signatory/pkg/utils/aws"
)

const (
	readCapacityUnits  = 5
	writeCapacityUnits = 5
	defaultTable       = "encrypted_keys"
)

type awsStorageConfig struct {
	awsutils.Config `yaml:",inline"`
	Table           string `yaml:"table"`
}

func (c *awsStorageConfig) table() string {
	if c.Table != "" {
		return c.Table
	}
	return defaultTable
}

type awsStorage struct {
	cfg    awsStorageConfig
	client *dynamodb.Client
}

func newAWSStorage(ctx context.Context, config *awsStorageConfig) (*awsStorage, error) {
	cfg, err := config.Config.NewAWSConfig(ctx)
	if err != nil {
		return nil, err
	}
	client := dynamodb.NewFromConfig(cfg)
	a := awsStorage{
		client: client,
		cfg:    *config,
	}
	if err := awsutils.DynamoDBMaybeCreateTable(ctx, client, a.makeCreateTableInput()); err != nil {
		return nil, err
	}
	return &a, nil
}

func (a *awsStorage) makeCreateTableInput() *dynamodb.CreateTableInput {
	return &dynamodb.CreateTableInput{
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("pkh"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("pkh"),
				KeyType:       types.KeyTypeHash,
			},
		},
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(readCapacityUnits),
			WriteCapacityUnits: aws.Int64(writeCapacityUnits),
		},
		TableName: aws.String(a.cfg.table()),
	}
}

type awsResult struct {
	err error
	out *dynamodb.ScanOutput
}

type dbItem struct {
	PKH   string `dynamodbav:"pkh"`
	Value []byte `dynamodbav:"value"`
}

func (r *awsResult) Result() iter.Seq[*encryptedKey] {
	return func(yield func(*encryptedKey) bool) {
		for _, item := range r.out.Items {
			var parsed dbItem
			if err := attributevalue.UnmarshalMap(item, &parsed); err != nil {
				r.err = err
				return
			}
			pkh, err := b58.ParsePublicKeyHash([]byte(parsed.PKH))
			if err != nil {
				r.err = err
				return
			}
			key := encryptedKey{
				PublicKeyHash:       pkh,
				EncryptedPrivateKey: parsed.Value,
			}
			if !yield(&key) {
				return
			}
		}
	}
}

func (r *awsResult) Err() error { return r.err }

func (a *awsStorage) GetKeys(ctx context.Context) (result[*encryptedKey], error) {
	out, err := a.client.Scan(ctx, &dynamodb.ScanInput{
		TableName: aws.String(a.cfg.table()),
	})
	if err != nil {
		return nil, err
	}
	return &awsResult{
		out: out,
	}, nil
}

func (a *awsStorage) ImportKey(ctx context.Context, encryptedKey *encryptedKey) error {
	item, err := attributevalue.MarshalMap(&dbItem{
		PKH:   encryptedKey.PublicKeyHash.String(),
		Value: encryptedKey.EncryptedPrivateKey,
	})
	if err != nil {
		return err
	}
	_, err = a.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(a.cfg.table()),
		Item:      item,
	})
	return err
}
