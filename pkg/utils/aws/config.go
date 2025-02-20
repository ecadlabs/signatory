package aws

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// Config contains AWS KMS backend configuration
type Config struct {
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	SessionToken    string `yaml:"session_token"`
	Region          string `yaml:"region"`
}

func (c *Config) GetAccessKeyID() string     { return c.AccessKeyID }
func (c *Config) GetSecretAccessKey() string { return c.SecretAccessKey }
func (c *Config) GetSessionToken() string    { return c.SessionToken }
func (c *Config) GetRegion() string          { return c.Region }

var (
	_ ConfigProvider = (*Config)(nil)
	_ RegionProvider = (*Config)(nil)
)

type ConfigProvider interface {
	GetAccessKeyID() string
	GetSecretAccessKey() string
	GetSessionToken() string
}

type RegionProvider interface {
	GetRegion() string
}

func NewAWSConfig(ctx context.Context, provider ConfigProvider) (aws.Config, error) {
	if provider != nil {
		if v := provider.GetAccessKeyID(); v != "" {
			os.Setenv("AWS_ACCESS_KEY_ID", v)
		}
		if v := provider.GetSecretAccessKey(); v != "" {
			os.Setenv("AWS_SECRET_ACCESS_KEY", v)
		}
		if v := provider.GetSessionToken(); v != "" {
			os.Setenv("AWS_SESSION_TOKEN", v)
		}
		if rp, ok := provider.(RegionProvider); ok {
			if v := rp.GetRegion(); v != "" {
				os.Setenv("AWS_REGION", v)
			}
		}
	}
	return awsconfig.LoadDefaultConfig(ctx)
}
