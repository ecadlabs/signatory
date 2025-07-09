package new_integration_test

import (
	"os/exec"
)

func OctezClient(arg ...string) ([]byte, error) {
	var cmd = "docker"
	var args = []string{"exec", "tezos-client", "octez-client", "-E", "http://tezos-node:18731"}
	args = append(args, arg...)
	return exec.Command(cmd, args...).CombinedOutput()
}

func clean_tezos_folder() {
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
