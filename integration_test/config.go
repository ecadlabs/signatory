package integrationtest

import (
	"log"
	"os"

	yaml "gopkg.in/yaml.v3"
)

/*
  jwt:
    users:
      user_name1:
        password: password1
		 # Secret used to sign JWT tokens
        secret: secret1
        tok_expiry: 2h10m40s
      user_name2:
        password: password2
        secret: secret2
        tok_expiry: 2h10m40s
*/

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
		log.Fatal(err)
	}
	if err = os.WriteFile(file, yamlFile, 0644); err != nil {
		log.Fatal(err)
	}

	return nil
}
