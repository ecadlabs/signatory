package config

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/go-playground/validator.v9"
	yaml "gopkg.in/yaml.v2"
)

// ServerConfig contains the information necessary to the tezos signing server
type ServerConfig struct {
	Port        int `yaml:"port" validate:"gte=0,lte=65535"`
	UtilityPort int `yaml:"utility_port" validate:"gte=0,lte=65535"`
}

// YubiConfig contains the information necessary to use the Yubi HSM backend
type YubiConfig struct {
	Host      string `yaml:"host" validate:"required,hostname"`
	Password  string `yaml:"password" validate:"required"`
	AuthKeyID uint16 `yaml:"auth_key_id" validate:"required"`
}

// AzureConfig contains the information necessary to use the Azure Key Vault backend
type AzureConfig struct {
	ClientID       string   `yaml:"client_id" validate:"required"`
	ClientSecret   string   `yaml:"client_secret" validate:"required,uuid4"`
	DirectoryID    string   `yaml:"tenant_id" validate:"required,uuid4"`
	SubscriptionID string   `yaml:"subscription" validate:"required,uuid4"`
	ResourceGroup  string   `yaml:"resource_group" validate:"required"`
	Vault          string   `yaml:"vault" validate:"required"`
	Keys           []string `yaml:"keys"`
}

// CloudKMSVaultConfig contains Google Cloud KMS backend configuration
type CloudKMSVaultConfig struct {
	ServiceAccountKey string `yaml:"service_account_key"`
	Project           string `yaml:"project" validate:"required"`
	Location          string `yaml:"location" validate:"required"`
	KeyRing           string `yaml:"key_ring" validate:"required"`
}

// KeyRingName returns full Google Cloud KMS key ring path
func (c *CloudKMSVaultConfig) KeyRingName() string {
	return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", c.Project, c.Location, c.KeyRing)
}

// TezosConfig contains the configuration related to tezos network
type TezosConfig = map[string]TezosPolicy

// TezosPolicy contains policy definition for a specific address
type TezosPolicy struct {
	AllowedOperations []string `yaml:"allowed_operations" validate:"dive,oneof=generic block endorsement"`
	AllowedKinds      []string `yaml:"allowed_kinds" validate:"dive,oneof=transaction proposal ballot reveal delegation"`
	LogPayloads       bool     `yaml:"log_payloads"`
}

// Config contains all the configuration necessary to run the signatory
type Config struct {
	Yubi   []YubiConfig  `yaml:"yubi"`
	Azure  []AzureConfig `yaml:"azure"`
	Tezos  TezosConfig   `yaml:"tezos" validate:"dive,keys,startswith=tz1|startswith=tz2|startswith=tz3,len=36,endkeys"`
	Server ServerConfig  `yaml:"server"`
}

func (c *Config) Validate() (bool, string) {
	err := validator.New().Struct(c)
	if err != nil {
		msg := ""
		for _, err := range err.(validator.ValidationErrors) {
			msg = fmt.Sprintf("%s%s (%s) not valid according to rule: %s %s\n", msg, err.Namespace(), err.Value(), err.Tag(), err.Param())
		}
		return false, msg
	}
	return true, ""
}

// Read read the config from a file
func (c *Config) Read(file string) error {
	yamlFile, _ := ioutil.ReadFile(file)
	err := yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return fmt.Errorf("Unmarshal: %v", err)
	}

	return nil
}
