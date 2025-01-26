package aws

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// Config contains AWS KMS backend configuration
type Config struct {
	AccessKeyID string `yaml:"access_key_id"`
	AccessKey   string `yaml:"secret_access_key"`
	Region      string `yaml:"region"`
}

func (config *Config) NewAWSConfig(ctx context.Context) (aws.Config, error) {
	if config.AccessKeyID != "" {
		os.Setenv("AWS_ACCESS_KEY_ID", config.AccessKeyID)
		os.Setenv("AWS_SECRET_ACCESS_KEY", config.AccessKey)
	}
	if config.Region != "" {
		os.Setenv("AWS_REGION", config.Region)
	}
	return awsconfig.LoadDefaultConfig(ctx)
}
