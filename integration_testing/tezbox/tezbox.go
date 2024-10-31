package tezbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/protocol/core"
	"github.com/hjson/hjson-go/v4"
	log "github.com/sirupsen/logrus"
)

const (
	nodePort       = "8732"
	startupTimeout = time.Minute
	initFile       = "/tezbox/context/data/tezbox-initialized"
)

func Must[T any](x T, err error) T {
	if err != nil {
		panic(err)
	}
	return x
}

type AccountConfig struct {
	PublicKey  gotez.PublicKey `json:"pk"`
	PrivateKey string          `json:"sk"`
	Balance    uint64          `json:"balance"`
}

type Accounts map[string]*AccountConfig

type AccountsConfig struct {
	Bakers  Accounts
	Regular Accounts
}

type accountConfig struct {
	PublicKeyHash gotez.PublicKeyHash `json:"pkh"`
	PublicKey     gotez.PublicKey     `json:"pk"`
	PrivateKey    string              `json:"sk"`
	Balance       uint64              `json:"balance"`
}

func newAccountConfig(c *AccountConfig) *accountConfig {
	return &accountConfig{
		PublicKeyHash: c.PublicKey.Hash(),
		PublicKey:     c.PublicKey,
		PrivateKey:    c.PrivateKey,
		Balance:       c.Balance,
	}
}

func newAccounts(a Accounts) map[string]*accountConfig {
	out := make(map[string]*accountConfig, len(a))
	for k, v := range a {
		out[k] = newAccountConfig(v)
	}
	return out
}

func (c *AccountsConfig) Write(dir string) ([]string, error) {
	acc, err := hjson.Marshal(newAccounts(c.Regular))
	if err != nil {
		return nil, err
	}
	bakers, err := hjson.Marshal(newAccounts(c.Bakers))
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(filepath.Join(dir, "accounts.hjson"), acc, 0666); err != nil {
		return nil, err
	}
	return []string{"accounts.hjson", "bakers.hjson"}, os.WriteFile(filepath.Join(dir, "bakers.hjson"), bakers, 0666)
}

type Container struct {
	id string
}

type ServiceConfig struct {
	Version  string
	Accounts *AccountsConfig
	Protocol *gotez.ProtocolHash
}

type ascendModuleStatus struct {
	State   string `json:"state"`
	Started uint64 `json:"started"`
}

type ascendServiceStatus struct {
	Ok     bool `json:"ok"`
	Status map[string]*ascendModuleStatus
}

type ascendStatus map[string]*ascendServiceStatus

func Start(cfg *ServiceConfig) (*Container, error) {
	log.Infof("Starting TezBox %s %s", cfg.Version, core.ProtocolShortName(cfg.Protocol))
	tmpDir, err := os.MkdirTemp("", "tezbox")
	if err != nil {
		return nil, err
	}
	args := []string{"container", "run", "--detach", "--rm", "--publish", nodePort + ":" + nodePort}
	if cfg.Accounts != nil {
		confFiles, err := cfg.Accounts.Write(tmpDir)
		if err != nil {
			return nil, err
		}
		for _, c := range confFiles {
			args = append(args, "-v", filepath.Join(tmpDir, c)+":"+filepath.Join("/tezbox/configuration", c))
		}
	}
	args = append(args, fmt.Sprintf("ghcr.io/tez-capital/tezbox:tezos-%s", cfg.Version), cfg.Protocol.String())
	log.Infof("docker args: %s", strings.Join(args, " "))
	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		return nil, err
	}
	cid := strings.TrimSpace(string(out))
	log.Infof("Container id: %s", cid)

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	log.Info("Waiting for node to be ready")
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		out, err := exec.Command("docker", "container", "exec", cid, "asctl", "status", "node").Output()
		if err == nil {
			var response ascendStatus
			if err := json.Unmarshal(out, &response); err != nil {
				return nil, err
			}
			if s, ok := response["node"]; ok && s.Ok {
				if mod, ok := s.Status["default"]; ok && mod.State == "active" {
					break
				}
			}
		}
		time.Sleep(time.Second)
	}

	return &Container{id: cid}, nil
}

func (c *Container) Exec(name string, args ...string) error {
	v := []string{"container", "exec", c.id, name}
	v = append(v, args...)
	return exec.Command("docker", v...).Run()
}

func (c *Container) ExecLog(name string, args ...string) error {
	v := []string{"container", "exec", c.id, name}
	v = append(v, args...)
	cmd := exec.Command("docker", v...)
	l := log.StandardLogger().Writer()
	cmd.Stdout = l
	cmd.Stderr = l
	return cmd.Run()
}

func (c *Container) Stop() error {
	log.Info("Stopping TezBox...")
	return exec.Command("docker", "container", "stop", c.id).Run()
}
