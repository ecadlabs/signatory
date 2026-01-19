package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

func OctezClient(arg ...string) ([]byte, error) {
	var cmd = "docker"
	var args = []string{"exec", "tezos-client", "octez-client"}
	args = append(args, arg...)
	return exec.Command(cmd, args...).CombinedOutput()
}

func Clean_tezos_folder() {
	delete_contracts_aliases()
	delete_wallet_lock()
	delete_watermark_files()
}

func delete_wallet_lock() {
	var cmd = "docker"
	var args = []string{"exec", "tezos-client", "rm", "-f", "/home/tezos/.tezos-client/wallet_lock"}
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		panic("Clean tezos: Failed to delete wallet lock: " + string(out))
	}
}

func delete_contracts_aliases() {
	var cmd = "docker"
	var args = []string{"exec", "tezos-client", "rm", "-f", "/home/tezos/.tezos-client/contracts"}
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		panic("Clean tezos: Failed to delete contracts: " + string(out))
	}
}

func delete_watermark_files() {
	var cmd = "docker"
	var args = []string{"exec", "tezos-client", "/bin/sh", "-c", "rm -f /home/tezos/.tezos-client/*_highwatermarks"}
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		panic("Clean tezos: Failed to delete watermarks: " + string(out))
	}
}

func GetCurrentProtocol() (string, error) {
	out, err := OctezClient("rpc", "get", "/chains/main/blocks/head/metadata")
	if err != nil {
		return "", err
	}
	var metadata struct {
		Protocol string `json:"protocol"`
	}
	// Find the line that starts with '{' and parse JSON from that line (Skip warnings)
	lines := bytes.Split(out, []byte("\n"))
	start := -1
	for i, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) > 0 && line[0] == '{' {
			start = i
			break
		}
	}
	if start == -1 {
		return "", fmt.Errorf("no JSON object found in output: %s", string(out))
	}
	out = bytes.Join(lines[start:], []byte("\n"))

	if err := json.Unmarshal(out, &metadata); err != nil {
		return "", err
	}

	return metadata.Protocol, nil
}

func GetChainID(args ...string) (string, error) {
	commandArgs := append(args, "rpc", "get", "/chains/main/chain_id")
	out, err := OctezClient(commandArgs...)
	if err != nil {
		return "", err
	}
	lines := bytes.Split(out, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) > 0 && line[0] == '"' {
			var chainID string
			if err := json.Unmarshal(line, &chainID); err != nil {
				return "", err
			}
			return chainID, nil
		}
	}
	return "", fmt.Errorf("no chain_id found in output: %s", string(out))
}
