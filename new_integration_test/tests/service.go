package new_integration_test

import (
	"fmt"
	"os/exec"
)

func Restart_signatory() {
	_, err := exec.Command("docker", "compose", "stop", "signatory").CombinedOutput()
	if err != nil {
		panic("failed to stop signatory")
	}
	out, err := exec.Command("docker", "compose", "up", "-d", "--wait", "signatory").CombinedOutput()
	if err != nil {
		fmt.Println("restart signatory: failed to start: " + string(out))
		panic("failed to start signatory during restart")
	}
}

func Backup_then_update_config(c Config) {
	backupFilename := ConfigFilename + ".bak"
	_, err := exec.Command("cp", ConfigFilename, backupFilename).CombinedOutput()
	if err != nil {
		panic("failed to backup config")
	}
	err = c.Write()
	if err != nil {
		panic("failed to write new config")
	}
}

func Restore_config() {
	backupFilename := ConfigFilename + ".bak"
	_, err := exec.Command("mv", backupFilename, ConfigFilename).CombinedOutput()
	if err != nil {
		panic("failed to restore original config")
	}
	Restart_signatory()
}

func Rstart_stack() {
	_, err := exec.Command("docker", "compose", "kill").CombinedOutput()
	if err != nil {
		panic("failed to kill stack")
	}
	_, err = exec.Command("docker", "compose", "up", "-d", "--wait").CombinedOutput()
	if err != nil {
		panic("failed to up stack")
	}
}
