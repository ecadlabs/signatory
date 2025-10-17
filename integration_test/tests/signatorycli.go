package tests

import (
	"os/exec"
)

func SignatoryCli(arg ...string) ([]byte, error) {
	var cmd = "docker"
	var args = []string{"exec", "signatory", "signatory-cli"}
	args = append(args, arg...)
	return exec.Command(cmd, args...).CombinedOutput()
}
