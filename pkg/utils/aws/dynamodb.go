package aws

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/smithy-go"
	log "github.com/sirupsen/logrus"
)

func DynamoDBMaybeCreateTable(ctx context.Context, client *dynamodb.Client, input *dynamodb.CreateTableInput) error {
	_, err := client.CreateTable(ctx, input)
	if err != nil {
		var serr smithy.APIError
		if errors.As(err, &serr) && serr.ErrorCode() == "ResourceInUseException" {
			return nil
		}
		return err
	}
	log.WithField("table", *input.TableName).Info("table created")
	waiter := dynamodb.NewTableExistsWaiter(client)
	return waiter.Wait(context.TODO(), &dynamodb.DescribeTableInput{
		TableName: aws.String(*input.TableName),
	}, time.Minute*5) // give excess time
}
