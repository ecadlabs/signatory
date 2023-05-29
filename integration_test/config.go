package integrationtest

import (
	"os"

	yaml "gopkg.in/yaml.v3"
)

const (
	filename = "signatory.yaml"
)

type Config struct {
	Server ServerConfig            `yaml:"server"`
	Vaults map[string]*VaultConfig `yaml:"vaults"`
	Tezos  TezosConfig             `yaml:"tezos"`
}

type JwtConfig struct {
	Users map[string]*JwtUserData `yaml:"users"`
}

type JwtUserData struct {
	Password string `yaml:"password"`
	Secret   string `yaml:"secret"`
	Exp      uint64 `yaml:"jwt_exp"`
}

type ServerConfig struct {
	Address        string    `yaml:"address"`
	UtilityAddress string    `yaml:"utility_address"`
	Keys           []string  `yaml:"authorized_keys,omitempty"`
	Jwt            JwtConfig `yaml:"jwt,omitempty"`
}

type TezosConfig = map[string]*TezosPolicy

type TezosPolicy struct {
	Allow       map[string][]string `yaml:"allow"`
	LogPayloads bool                `yaml:"log_payloads"`
}

type VaultConfig struct {
	Driver string             `yaml:"driver"`
	Conf   map[string]*string `yaml:"config"`
}

type FileVault struct {
	File string `yaml:"file"`
}

func (c *Config) Read() error {
	yamlFile, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	if err = yaml.Unmarshal(yamlFile, c); err != nil {
		return err
	}
	return nil
}

func (c *Config) Write() error {
	yamlFile, err := yaml.Marshal(c)
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(filename, yamlFile, 0644); err != nil {
		panic(err)
	}
	return nil
}
