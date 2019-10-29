package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	yaml "gopkg.in/yaml.v3"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

type testCase struct {
	Account        string `yaml:"account"`
	Address        string `yaml:"address"`
	PublicKey      string `yaml:"public_key"`
	Code           int    `yaml:"http_code"`
	SignatureValid bool   `yaml:"expect_signature_valid"`
}

type Config struct {
	Signatory                 string     `yaml:"signatory"`
	SignatoryURL              string     `yaml:"signatory_url"`
	SignatoryConfig           string     `yaml:"signatory_config"`
	SignatoryWorkingDirectory string     `yaml:"signatory_wdir"`
	TezosClientDir            string     `yaml:"tezos_client_dir"`
	TestCases                 []testCase `yaml:"test_cases"`
}

func (c *Config) Read(file string) error {
	yamlFile, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	if err = yaml.Unmarshal([]byte(os.ExpandEnv(string(yamlFile))), c); err != nil {
		return err
	}

	return nil
}

var config *Config = &Config{
	SignatoryURL: "http://localhost:6732",
}

func TestMain(m *testing.M) {
	err := config.Read("./config.yaml")
	if err != nil {
		panic(err)
	}
	// Start signatory
	cmd := exec.Command("go", "run", config.Signatory, "-c", config.SignatoryConfig)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Dir = config.SignatoryWorkingDirectory
	buf := new(bytes.Buffer)
	cmd.Stdout = os.Stdout
	cmd.Stderr = buf

	err = cmd.Start()
	fmt.Fprintln(cmd.Stderr)
	if err != nil {
		panic(err)
	}
	time.Sleep(20 * time.Second)
	code := m.Run()

	defer func() {
		fmt.Printf("Signatory output: \n%s", buf.String())
		os.Exit(code)
	}()
	// Do not close the underlying go process
	err = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if err != nil {
		panic(err)
	}
}

func VerifySignature(data string, account string, signature string) error {
	cliCmd := fmt.Sprintf("check that 0x%s was signed by %s to produce %s", data, account, signature)
	cmd := exec.Command("docker", strings.Fields("run -t --network host -v "+config.TezosClientDir+":/var/run/tezos/client tezos/tezos:babylonnet tezos-client -A rpcalpha.tzbeta.net -P 443 -S "+cliCmd)...)
	return cmd.Run()
}

type SignatureResponse struct {
	Signature string `json:"signature"`
}

func GenEndorsement(blockLevel int32, c testCase) string {
	return fmt.Sprintf("02%08x080808080808080808080808080808080808080808080808080808080505050a080808080808080808080808080808080808080808080808080808", blockLevel)
}

func GenBlock(blockLevel int32, c testCase) string {
	return fmt.Sprintf("01%08x%08x011dc1a5b193d1bf8ad500c26209ebdc75f0e71e906de9b7cb45b91f9880037842000000005d8e4e8104a3e226c7b4a8700c985e470581dfdd13067e808d8b163fe838c42abda7f478e50000001100000001010000000800000000000338152851a65d186d0cfa747b890ca9086aa0feef05b573aa82c3a32fba55e1c5f99f04d2112233445566778800", 11111111, blockLevel)
}

func GenTransaction(blockLevel int32, c testCase) string {
	return "03ce69c5713dac3537254e7be59759cf59c15abd530d10501ccf9028a5786314cf08000002298c03ed7d454a101eb7022bc95f7e5f41ac78d0860303c8010080c2d72f0000e7670f32038107a59a2b9cfefae36ea21f5aa63c00"
}

type DataFunc = func(level int32, c testCase) string

type SigCase struct {
	Name           string
	genFunc        DataFunc
	CheckWatermark bool
}

func TestFileBackendSign(t *testing.T) {
	f := []SigCase{
		SigCase{
			Name:           "Block",
			genFunc:        GenBlock,
			CheckWatermark: true,
		},
		SigCase{
			Name:           "Endorsement",
			genFunc:        GenEndorsement,
			CheckWatermark: true,
		},
		SigCase{
			Name:           "Generic",
			genFunc:        GenTransaction,
			CheckWatermark: false,
		},
	}

	for idx, sigCase := range f {
		for i, c := range config.TestCases {
			data := sigCase.genFunc((100*int32(idx))+int32(i), c)
			buf := strings.NewReader("\"" + data + "\"")
			resp, err := http.Post(config.SignatoryURL+"/keys/"+c.Address, "application/json", buf)

			if err != nil {
				t.Fatal(err)
			}

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			if resp.StatusCode != c.Code {
				t.Fatalf("(%s/%s) Received %d expected %d", c.Account, sigCase.Name, resp.StatusCode, c.Code)
			}

			signature := SignatureResponse{}

			err = json.Unmarshal(body, &signature)

			if err != nil {
				t.Fatal(err)
			}

			err = VerifySignature(data, c.Account, signature.Signature)
			if err != nil && c.SignatureValid {
				t.Fatalf("(%s/%s) Signature verification failed: %s", c.Account, sigCase.Name, err)
			} else if err == nil && !c.SignatureValid {
				t.Fatal("Expected error and got none")
			}

			if c.SignatureValid {
				// Check if watermark works
				buf = strings.NewReader("\"" + data + "\"")
				respWaterMark, err := http.Post(config.SignatoryURL+"/keys/"+c.Address, "application/json", buf)

				if err != nil {
					t.Fatal(err)
				}

				if sigCase.CheckWatermark && respWaterMark.StatusCode != 403 {
					t.Fatalf("(%s/%s) Watermark check failed expected 403 got %d, data: %s", c.Account, sigCase.Name, respWaterMark.StatusCode, data)
				} else if !sigCase.CheckWatermark && respWaterMark.StatusCode != 200 {
					t.Fatalf("(%s/%s) Watermark check failed expected 200 got %d, data: %s", c.Account, sigCase.Name, respWaterMark.StatusCode, data)
				}
			}

			t.Logf("(%s) Success", c.Account)
		}
	}
}

func TestFileBackendGetPubKey(t *testing.T) {
	for _, c := range config.TestCases {
		resp, err := http.Get(config.SignatoryURL + "/keys/" + c.Address)

		if err != nil {
			t.Fatal(err)
		}

		body := struct {
			PublicKey string `json:"public_key"`
		}{}

		err = json.NewDecoder(resp.Body).Decode(&body)

		if err != nil {
			t.Fatal(err)
		}

		if body.PublicKey != c.PublicKey {
			t.Fatalf("(%s) Received public key: %s , expected %s", c.Account, body.PublicKey, c.PublicKey)
		}

		t.Logf("(%s) Success", c.Account)
	}
}
