package gcp

import (
	"context"

	"google.golang.org/api/option"
)

type Config struct {
	ApplicationCredentialsData string `yaml:"application_credentials_data"`
	ApplicationCredentials     string `yaml:"application_credentials"`
}

func (c *Config) GetApplicationCredentialsData() string { return c.ApplicationCredentialsData }
func (c *Config) GetApplicationCredentials() string     { return c.ApplicationCredentials }

var (
	_ ConfigProvider = (*Config)(nil)
)

type ConfigProvider interface {
	GetApplicationCredentialsData() string
	GetApplicationCredentials() string
}

func NewGCPOption(ctx context.Context, provider ConfigProvider) ([]option.ClientOption, error) {
	if provider != nil {
		if v := provider.GetApplicationCredentialsData(); v != "" {
			return []option.ClientOption{option.WithCredentialsJSON([]byte(v))}, nil
		} else if v := provider.GetApplicationCredentials(); v != "" {
			return []option.ClientOption{option.WithCredentialsFile(v)}, nil
		}
	}
	return []option.ClientOption{}, nil
}
