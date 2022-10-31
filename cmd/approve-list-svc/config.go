package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/tezos"
	yaml "gopkg.in/yaml.v3"
)

type Config struct {
	Address        string   `yaml:"address"`
	PrivateKey     string   `yaml:"private_key"`
	PrivateKeyFile string   `yaml:"private_key_file"`
	List           []string `yaml:"list"`
}

func (conf *Config) Addresses() ([]net.IP, []*net.IPNet, error) {
	var (
		ips  []net.IP
		nets []*net.IPNet
	)
	for _, addr := range conf.List {
		if _, n, err := net.ParseCIDR(addr); err == nil {
			nets = append(nets, n)
		} else {
			if ip := net.ParseIP(addr); ip != nil {
				ips = append(ips, ip)
			} else {
				return nil, nil, fmt.Errorf("invalid address: %s", addr)
			}
		}
	}
	return ips, nets, nil
}

func (conf *Config) GetPrivateKey() (cryptoutils.PrivateKey, error) {
	var keyData []byte
	if conf.PrivateKey != "" {
		if pk, err := tezos.ParsePrivateKey(conf.PrivateKey, nil); err == nil {
			return pk, nil
		} else {
			keyData = []byte(conf.PrivateKey)
		}
	} else {
		if conf.PrivateKeyFile == "" {
			return nil, nil
		}
		var err error
		if keyData, err = ioutil.ReadFile(conf.PrivateKeyFile); err != nil {
			return nil, err
		}
	}

	b, _ := pem.Decode(keyData)
	if b == nil {
		return nil, errors.New("can't parse private key PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := key.(cryptoutils.PrivateKey)
	if !ok {
		return nil, errors.New("unexpected private key type")
	}
	return pk, nil
}

func ReadConfig(file string) (*Config, error) {
	yamlFile, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var c Config
	if err = yaml.Unmarshal(yamlFile, &c); err != nil {
		return nil, err
	}

	return &c, nil
}
