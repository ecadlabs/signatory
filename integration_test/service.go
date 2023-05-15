package integrationtest

import (
	"os"
	"os/exec"
)

func restart_signatory() {
	_, err := exec.Command("docker", "compose", "--env-file", "env."+os.Getenv("TESTENV"), "-f", "./docker-compose.yml", "stop", "signatory").CombinedOutput()
	if err != nil {
		panic("failed to stop signatory")
	}
	_, err = exec.Command("docker", "compose", "--env-file", "env."+os.Getenv("TESTENV"), "-f", "./docker-compose.yml", "up", "-d", "--wait", "signatory").CombinedOutput()
	if err != nil {
		panic("failed to start signatory during restart")
	}
}

func backup_then_update_config(c Config) {
	_, err := exec.Command("cp", "signatory.yaml", "signatory.original.yaml").CombinedOutput()
	if err != nil {
		panic("failed to backup config")
	}
	err = c.Write("signatory.yaml")
	if err != nil {
		panic("failed to write new config")
	}
}

func restore_config() {
	_, err := exec.Command("mv", "signatory.original.yaml", "signatory.yaml").CombinedOutput()
	if err != nil {
		panic("failed to restore original config")
	}
	restart_signatory()
}

func restart_stack() {
	_, err := exec.Command("docker", "compose", "--env-file", "env."+os.Getenv("TESTENV"), "-f", "./docker-compose.yml", "kill").CombinedOutput()
	if err != nil {
		panic("failed to kill stack")
	}
	_, err = exec.Command("docker", "compose", "-f", "./docker-compose.yml", "up", "-d", "--wait").CombinedOutput()
	if err != nil {
		panic("failed to up stack")
	}
}
