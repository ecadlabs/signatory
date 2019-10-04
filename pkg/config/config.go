package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"gopkg.in/go-playground/validator.v9"
	yaml "gopkg.in/yaml.v3"
)

// ServerConfig contains the information necessary to the tezos signing server
type ServerConfig struct {
	Address        string `yaml:"address" validate:"hostport"`
	UtilityAddress string `yaml:"utility_address" validate:"hostport"`
}

/*
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
*/

// TezosConfig contains the configuration related to tezos network
type TezosConfig map[string]*TezosAddressConfig

// TezosAddressConfig contains the configuration related to tezos network
type TezosAddressConfig struct {
	Policy *TezosPolicy `yaml:"policy"`
}

// TezosPolicy contains policy definition for a specific address
type TezosPolicy struct {
	AllowedOperations []string `yaml:"allowed_operations" validate:"dive,oneof=generic block endorsement"`
	AllowedKinds      []string `yaml:"allowed_kinds" validate:"dive,oneof=transaction proposal ballot reveal delegation"`
	LogPayloads       bool     `yaml:"log_payloads"`
}

// VaultConfig represents single vault instance
type VaultConfig struct {
	Driver string     `yaml:"driver" validate:"required"`
	Config *yaml.Node `yaml:"config"`
}

// Config contains all the configuration necessary to run the signatory
type Config struct {
	/*
		Yubi   []*YubiConfig  `yaml:"yubi"`
		Azure  []*AzureConfig `yaml:"azure"`
	*/
	Vaults map[string]*VaultConfig `yaml:"vaults" validate:"gt=0,dive,required"`
	Tezos  TezosConfig             `yaml:"tezos" validate:"dive,keys,startswith=tz1|startswith=tz2|startswith=tz3,len=36,endkeys"`
	Server ServerConfig            `yaml:"server"`
}

func FormatValidationError(err error) error {
	if list, ok := err.(validator.ValidationErrors); ok {
		var msgs []string
		for _, e := range list {
			msgs = append(msgs, fmt.Sprintf("%s (%s) not valid according to rule: %s %s", e.Namespace(), e.Value(), e.Tag(), e.Param()))
		}
		err = errors.New(strings.Join(msgs, ","))
	}
	return err
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

func Validator() *validator.Validate {
	validate := validator.New()
	validate.RegisterValidation("hostport", func(fl validator.FieldLevel) bool {
		_, _, err := net.SplitHostPort(fl.Field().String())
		return err == nil
	})
	return validate
}
