package config

import (
	"encoding/json"
	"errors"
	"io/ioutil"

	"github.com/go-playground/validator/v10"
	yaml "gopkg.in/yaml.v3"
)

// ServerConfig contains the information necessary to the tezos signing server
type ServerConfig struct {
	Address        string          `yaml:"address" validate:"hostname_port"`
	UtilityAddress string          `yaml:"utility_address" validate:"hostname_port"`
	AuthorizedKeys *AuthorizedKeys `yaml:"authorized_keys"`
}

// TezosConfig contains the configuration related to tezos network
type TezosConfig map[string]*TezosPolicy

// TezosPolicy contains policy definition for a specific address
type TezosPolicy struct {
	AllowedOperations []string        `yaml:"allowed_operations" validate:"dive,oneof=generic block endorsement"`
	AllowedKinds      []string        `yaml:"allowed_kinds" validate:"dive,oneof=endorsement seed_nonce_revelation double_endorsement_evidence double_baking_evidence activate_account ballot proposals reveal transaction origination delegation"`
	LogPayloads       bool            `yaml:"log_payloads"`
	AuthorizedKeys    *AuthorizedKeys `yaml:"authorized_keys"`
}

// VaultConfig represents single vault instance
type VaultConfig struct {
	Driver string    `yaml:"driver" validate:"required"`
	Config yaml.Node `yaml:"config"`
}

// Config contains all the configuration necessary to run the signatory
type Config struct {
	Vaults map[string]*VaultConfig `yaml:"vaults" validate:"dive,required"`
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
	return validator.New()
}

// AuthorizedKeys keeps list of authorized public keys
type AuthorizedKeys struct {
	value string
	list  []*AuthorizedKeys
}

// List returns all keys as a string slice
func (a *AuthorizedKeys) List() []string {
	if a.list != nil {
		var ret []string
		for _, v := range a.list {
			ret = append(ret, v.List()...)
		}
		return ret
	}
	return []string{a.value}
}

// UnmarshalYAML implements yaml.Unmarshaler
func (a *AuthorizedKeys) UnmarshalYAML(value *yaml.Node) error {
	var target interface{}
	switch value.Kind {
	case yaml.ScalarNode:
		target = &a.value
	case yaml.SequenceNode:
		target = &a.list
	default:
		return errors.New("can't decode YAML node")
	}
	if err := value.Decode(target); err != nil {
		return err
	}
	return nil
}

// MarshalJSON implements json.Marshaler
func (a *AuthorizedKeys) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.List())
}
