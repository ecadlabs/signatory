package vaults_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	integrationtest "github.com/ecadlabs/signatory/integration_test/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashiVault(t *testing.T) {

	roleid, secretid := hashiBootstrap()
	cn := hashiGetValidCN()
	address := "https://" + cn + ":8200"
	mountPoint := "transit/"

	var c integrationtest.Config
	c.Read()
	var v integrationtest.VaultConfig
	v.Driver = "hashicorpvault"
	v.Conf = map[string]interface{}{"address": &address, "roleID": &roleid, "secretID": &secretid, "transitConfig": map[string]string{"mountPoint": mountPoint}, "tlsCaCert": "/opt/hashicerts/vault-ca.pem"}
	c.Vaults["hashicorp"] = &v
	integrationtest.Update_config(c)
	defer integrationtest.Restore_config()

	pkh := hashiGetTz1()
	var p integrationtest.TezosPolicy
	p.LogPayloads = true
	p.Allow = map[string][]string{"generic": {"reveal", "transaction"}}
	c.Tezos[pkh] = &p
	c.Write()
	//os.Exit(0)
	integrationtest.Restart_signatory()

	out, err := integrationtest.OctezClient("import", "secret", "key", "hashitz1", "http://signatory:6732/"+pkh)
	assert.NoError(t, err)
	assert.Contains(t, string(out), "Tezos address added: "+pkh)
	defer integrationtest.OctezClient("forget", "address", "hashitz1", "--force")

	out, err = integrationtest.OctezClient("transfer", "100", "from", "alice", "to", "hashitz1", "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	out, err = integrationtest.OctezClient("transfer", "1", "from", "hashitz1", "to", "alice", "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	require.Contains(t, integrationtest.GetPublicKey(pkh), "edpk")
}

func hashiBootstrap() (roleId string, secretId string) {
	body, _ := json.Marshal(map[string]string{"policy": "path \"transit/*\" { capabilities = [\"list\", \"read\", \"create\", \"update\"]}"})
	code, res := hashiAPI(http.MethodPost, "sys/policy/transit-policy", body)
	hashiCheckErr(code, "create transit-policy")

	body, _ = json.Marshal(map[string]string{"type": "transit"})
	code, res = hashiAPI(http.MethodPost, "sys/mounts/transit", body)
	hashiCheckErr(code, "enable transit secrets engine")

	body, _ = json.Marshal(map[string]string{"type": "ed25519"})
	code, res = hashiAPI(http.MethodPost, "transit/keys/tz1key", body)
	hashiCheckErr(code, "generate a key")

	body, _ = json.Marshal(map[string]string{"type": "approle"})
	code, res = hashiAPI(http.MethodPost, "sys/auth/approle", body)
	hashiCheckErr(code, "enable auth method approle")

	body, _ = json.Marshal(map[string]string{"secret_id_ttl": "0m", "token_ttl": "10m", "token_max_ttl": "20m", "token_policies": "transit-policy"})
	code, res = hashiAPI(http.MethodPost, "auth/approle/role/my-approle", body)
	hashiCheckErr(code, "create an approle")

	code, res = hashiAPI(http.MethodGet, "auth/approle/role/my-approle/role-id", nil)
	hashiCheckErr(code, "get the role id")
	var rid HashiResponse
	dec := json.NewDecoder(bytes.NewReader(res))
	dec.Decode(&rid)
	roleid := rid.Data["role_id"]

	code, res = hashiAPI(http.MethodPost, "auth/approle/role/my-approle/secret-id", nil)
	hashiCheckErr(code, "generate new secret id")
	var sid HashiResponse
	dec = json.NewDecoder(bytes.NewReader(res))
	dec.Decode(&sid)
	secretid := sid.Data["secret_id"]

	return roleid, secretid
}

func hashiAPI(method string, path string, body []byte) (int, []byte) {
	url := "https://127.0.0.1:8200/v1/" + path
	reqbody := bytes.NewReader(body)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, reqbody)
	if err != nil {
		panic(err)
	}
	req.Header.Add("X-Vault-Token", "root")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return resp.StatusCode, bytes
}

type HashiResponse struct {
	Data map[string]string `json:"data"`
}

func hashiCheckErr(code int, message string) {
	if !(code >= 200 && code < 300) {
		panic("hashi config error: " + message + " : error code " + fmt.Sprint(code))
	}
}

func hashiGetTz1() string {
	out, err := integrationtest.SignatoryCli("list")
	if err != nil {
		panic("hashiGetTz1: signatory-cli returned an error: " + string(out))
	}
	var tz1 string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "tz1") && strings.Contains(line, "Public Key Hash") {
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.Contains(field, "tz1") {
					tz1 = field
				}
			}
		}
		if strings.Contains(line, "Hashicorp") {
			return tz1
		}
	}
	panic("Hashicorp PKH not found in signatory-cli list")
}

// the vault hostname in Signatory config file needs to match a CN in the SSL Cert
func hashiGetValidCN() string {
	//the cert autogenerated by hashi vault -dev-tls mode just so happens to include the container hash as a valid CN
	var cmd = "docker"
	var args = []string{"ps"}

	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		panic("hashiGetValidCN error: " + string(out))
	}
	var cn string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "hashi") {
			fields := strings.Fields(line)
			cn = fields[0]
			break
		}
	}
	if len(cn) < 12 {
		panic("hashiGetValidCN: did not discover a valid CN: " + cn)
	}
	return cn
}
