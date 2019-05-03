package config

import (
	"io/ioutil"
	"log"

	yaml "gopkg.in/yaml.v2"
)

// ServerConfig contains the information necessary to the tezos signing server
type ServerConfig struct {
	Port int `yaml:"port"`
}

// AzureConfig contains the information necessary to use the Azure Key Vault backend
type AzureConfig struct {
	ClientID       string `yaml:"client_id"`
	ClientSecret   string `yaml:"client_secret"`
	SubscriptionID string `yaml:"subscription"`
	Keys           []struct {
		KeyID string `yaml:"key_id"`
		Hash  string `yaml:"hash"`
		Alg   string `yaml:"alg"`
	}
}

// TezosConfig contains the configuration related to tezos network
type TezosConfig struct {
}

// Config contains all the configuration necessary to run the signatory
type Config struct {
	Azure  AzureConfig  `yaml:"azure"`
	Tezos  TezosConfig  `yaml:"tezos"`
	Server ServerConfig `yaml:"server"`
}

// Read read the config from a file
func (c *Config) Read(file string) *Config {
	yamlFile, err := ioutil.ReadFile(file)
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	return c
}
