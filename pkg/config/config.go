package config

import (
	"io/ioutil"
	"net"

	"gopkg.in/go-playground/validator.v9"
	yaml "gopkg.in/yaml.v3"
)

// ServerConfig contains the information necessary to the tezos signing server
type ServerConfig struct {
	Address        string `yaml:"address" validate:"hostport"`
	UtilityAddress string `yaml:"utility_address" validate:"hostport"`
}

// TezosConfig contains the configuration related to tezos network
type TezosConfig map[string]*TezosPolicy

// TezosPolicy contains policy definition for a specific address
type TezosPolicy struct {
	AllowedOperations []string `yaml:"allowed_operations" validate:"dive,oneof=generic block endorsement"`
	AllowedKinds      []string `yaml:"allowed_kinds" validate:"dive,oneof=endorsement seed_nonce_revelation double_endorsement_evidence double_baking_evidence activate_account ballot proposals reveal transaction origination delegation"`
	LogPayloads       bool     `yaml:"log_payloads"`
}

// VaultConfig represents single vault instance
type VaultConfig struct {
	Driver string    `yaml:"driver" validate:"required"`
	Config yaml.Node `yaml:"config"`
}

// Config contains all the configuration necessary to run the signatory
type Config struct {
	Vaults map[string]*VaultConfig `yaml:"vaults"`
	Tezos  TezosConfig             `yaml:"tezos" validate:"dive,keys,startswith=tz1|startswith=tz2|startswith=tz3,len=36,endkeys"`
	Server ServerConfig            `yaml:"server"`
}

var defaultConfig = Config{
	Server: ServerConfig{
		Address:        ":6732",
		UtilityAddress: ":9583",
	},
}

// Read read the config from a file
func (c *Config) Read(file string) error {
	yamlFile, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	if err = yaml.Unmarshal(yamlFile, c); err != nil {
		return err
	}

	return nil
}

func Default() *Config {
	c := defaultConfig
	return &c
}

func Validator() *validator.Validate {
	validate := validator.New()
	validate.RegisterValidation("hostport", func(fl validator.FieldLevel) bool {
		_, _, err := net.SplitHostPort(fl.Field().String())
		return err == nil
	})
	return validate
}
