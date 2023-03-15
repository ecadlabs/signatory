package config

import (
	"errors"
	"os"

	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/gotez/b58"
	"github.com/ecadlabs/gotez/hashmap"
	"github.com/go-playground/validator/v10"
	yaml "gopkg.in/yaml.v3"
)

// PolicyHook is an external service for secondary validation of sign requests
type PolicyHook struct {
	Address        string          `yaml:"address"`
	AuthorizedKeys *AuthorizedKeys `yaml:"authorized_keys"`
}

// ServerConfig contains the information necessary to the tezos signing server
type ServerConfig struct {
	Address        string          `yaml:"address" validate:"hostname_port"`
	UtilityAddress string          `yaml:"utility_address" validate:"hostname_port"`
	AuthorizedKeys *AuthorizedKeys `yaml:"authorized_keys"`
}

// TezosConfig contains the configuration related to tezos network
type TezosConfig = hashmap.HashMap[tz.EncodedPublicKeyHash, tz.PublicKeyHash, *TezosPolicy]

// TezosPolicy contains policy definition for a specific address
type TezosPolicy struct {
	Allow             map[string][]string `yaml:"allow"`
	AllowedOperations []string            `yaml:"allowed_operations"`
	AllowedKinds      []string            `yaml:"allowed_kinds"`
	LogPayloads       bool                `yaml:"log_payloads"`
	AuthorizedKeys    *AuthorizedKeys     `yaml:"authorized_keys"`
}

// VaultConfig represents single vault instance
type VaultConfig struct {
	Driver string    `yaml:"driver" validate:"required"`
	Config yaml.Node `yaml:"config"`
}

// Config contains all the configuration necessary to run the signatory
type Config struct {
	Vaults     map[string]*VaultConfig `yaml:"vaults" validate:"dive,required"`
	Tezos      TezosConfig             `yaml:"tezos" validate:"dive,keys,startswith=tz1|startswith=tz2|startswith=tz3|startswith=tz4,len=36,endkeys"`
	Server     ServerConfig            `yaml:"server"`
	PolicyHook *PolicyHook             `yaml:"policy_hook"`
	BaseDir    string                  `yaml:"base_dir" validate:"required"`
}

var defaultConfig = Config{
	Server: ServerConfig{
		Address:        ":6732",
		UtilityAddress: ":9583",
	},
	BaseDir: "/var/lib/signatory",
}

// Read read the config from a file
func (c *Config) Read(file string) error {
	yamlFile, err := os.ReadFile(file)
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
	value tz.PublicKey
	list  []*AuthorizedKeys
}

// List returns all keys as a string slice
func (a *AuthorizedKeys) List() []tz.PublicKey {
	if a.list != nil {
		var ret []tz.PublicKey
		for _, v := range a.list {
			ret = append(ret, v.List()...)
		}
		return ret
	}
	return []tz.PublicKey{a.value}
}

// UnmarshalYAML implements yaml.Unmarshaler
func (a *AuthorizedKeys) UnmarshalYAML(value *yaml.Node) (err error) {
	switch value.Kind {
	case yaml.ScalarNode:
		var pub tz.PublicKey
		pub, err = b58.ParsePublicKey([]byte(value.Value))
		a.value = pub

	case yaml.SequenceNode:
		err = value.Decode(&a.list)

	default:
		return errors.New("can't decode YAML node")
	}
	return err
}
