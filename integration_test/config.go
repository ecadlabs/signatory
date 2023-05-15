package integrationtest

import (
	"os"

	yaml "gopkg.in/yaml.v3"
)

type Config struct {
	Server ServerConfig            `yaml:"server"`
	Vaults map[string]*VaultConfig `yaml:"vaults"`
	Tezos  TezosConfig             `yaml:"tezos"`
}

type ServerConfig struct {
	Address        string   `yaml:"address"`
	UtilityAddress string   `yaml:"utility_address"`
	Keys           []string `yaml:"authorized_keys,omitempty"`
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

func (c *Config) Write(file string) error {
	yamlFile, err := yaml.Marshal(c)
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(file, yamlFile, 0644); err != nil {
		panic(err)
	}

	return nil
}
