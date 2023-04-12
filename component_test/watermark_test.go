package componenttest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

type SuccessResponse struct {
	Signature string `json:"signature"`
}

type FailureResponse struct {
	Id   string `json:"id"`
	Kind string `json:"kind"`
	Msg  string `json:"msg"`
}

type operationMap map[string]watermarkMap
type watermarkMap map[string]*watermarkData
type watermarkData struct {
	Round int32  `json:"round,omitempty"`
	Level int32  `json:"level"`
	Hash  string `json:"hash,omitempty"`
}

const (
	protocol = "http://"
	host     = "localhost"
	port     = "6732"
	pkh      = "tz1WGcYos3hL7GXYXjKrMnSFdkT7FyXnFBvf"
	url      = protocol + host + ":" + port + "/keys/" + pkh
)

type functionalTestCase struct {
	title               string
	signRequestBodies   []string
	expectedStatusCodes []int
	expectedResponses   []any
	watermarkBefore     operationMap
	watermarkAfter      operationMap
	chainID             string
}

var functionalTestCases = []functionalTestCase{
	{title: "double sign block level 2 round 0 no existing watermark",
		signRequestBodies: []string{
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277ae404b7528bb55c532567eb5a866e2a9e7d4e120d2627b4cfb58061756071d6f4a5630000002500000001020000000400000002000000040000000000000004ffffffff0000000400000006080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad12000000003e9dad7a000000000002\"",
		},
		expectedStatusCodes: []int{200, 409},
		expectedResponses: []any{SuccessResponse{Signature: "sigvRviWQVRQBm1yGucc2RdR57nhnnWSm9bHGBJW8AHfYZMfixXacD9ZEWQHLF2qFw6M8zve1j9NLHMaHu77tbQW3zk46UNL"},
			[]FailureResponse{{Id: "failure", Kind: "temporary", Msg: "block level 2 and round 0 already signed with different data"}}},
		watermarkBefore: nil,
		watermarkAfter:  operationMap{"block": {pkh: {Level: 2, Hash: "vh2i6wpkn9bGpw47r3RhnfHiCrLvzTvQT36AmEZNPPsKqcN7yecT", Round: 0}}},
		chainID:         "NetXo5iVw1vBoxM",
	},
}

func TestWatermark(t *testing.T) {
	for _, test := range functionalTestCases {
		t.Run(test.title, func(t *testing.T) {
			start_signatory()
			defer stop_signatory()
			mkdir()
			if test.watermarkBefore != nil {
				write_watermark_file(test.watermarkBefore, test.chainID+".json")
			}
			defer remove_watermark_files()
			for i, request := range test.signRequestBodies {
				code, message := request_sign(request)
				require.Equal(t, test.expectedStatusCodes[i], code)
				if code == 200 {
					var sr SuccessResponse
					dec := json.NewDecoder(bytes.NewReader(message))
					err := dec.Decode(&sr)
					require.Nil(t, err)
					require.Equal(t, test.expectedResponses[i], sr)
				} else {
					var fr []FailureResponse
					dec := json.NewDecoder(bytes.NewReader(message))
					err := dec.Decode(&fr)
					require.Nil(t, err)
					require.Equal(t, test.expectedResponses[i], fr)
				}
			}
			b := read_watermark_file(test.chainID)
			var om operationMap
			dec := json.NewDecoder(bytes.NewReader(b))
			err := dec.Decode(&om)
			require.Nil(t, err)
			require.Equal(t, test.watermarkAfter, om)
		})
	}
}

type concurrencyTestCase struct {
	title                  string
	description            string
	signRequestBodies      []string
	expectedSuccessCount   int
	expectedFailureCount   int
	expectedFailureCode    int
	expectedFailureMessage string
	watermarkBefore        operationMap
	watermarkAfter         operationMap
	chainID                string
}

var concurrencyTestCases = []concurrencyTestCase{
	{title: "10 concurrent, 2 distinct, requests, requesting double sign block level 2 round 0, no existing watermark",
		description: "this is a stress test to ensure that watermark file is not corrupted by concurrent requests. It also tests that Signatory will sign exact duplicate requests, ie, the hash in the watermark is used",
		signRequestBodies: []string{
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277ae404b7528bb55c532567eb5a866e2a9e7d4e120d2627b4cfb58061756071d6f4a5630000002500000001020000000400000002000000040000000000000004ffffffff0000000400000006080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad12000000003e9dad7a000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277ae404b7528bb55c532567eb5a866e2a9e7d4e120d2627b4cfb58061756071d6f4a5630000002500000001020000000400000002000000040000000000000004ffffffff0000000400000006080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad12000000003e9dad7a000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277ae404b7528bb55c532567eb5a866e2a9e7d4e120d2627b4cfb58061756071d6f4a5630000002500000001020000000400000002000000040000000000000004ffffffff0000000400000006080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad12000000003e9dad7a000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277ae404b7528bb55c532567eb5a866e2a9e7d4e120d2627b4cfb58061756071d6f4a5630000002500000001020000000400000002000000040000000000000004ffffffff0000000400000006080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad12000000003e9dad7a000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277ae404b7528bb55c532567eb5a866e2a9e7d4e120d2627b4cfb58061756071d6f4a5630000002500000001020000000400000002000000040000000000000004ffffffff0000000400000006080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad12000000003e9dad7a000000000002\"",
		},
		expectedSuccessCount:   5,
		expectedFailureCount:   5,
		expectedFailureMessage: "block level 2 and round 0 already signed with different data",
		expectedFailureCode:    409,
		watermarkBefore:        nil,
		watermarkAfter:         operationMap{"block": {pkh: {Level: 2, Hash: "cannot_predict_not_asserted_upon", Round: 0}}},
		chainID:                "NetXo5iVw1vBoxM",
	},
}

var (
	mutex sync.Mutex
	wg    sync.WaitGroup
	res   []string
	codes []int
)

func TestConcurrency(t *testing.T) {
	for _, test := range concurrencyTestCases {
		t.Run(test.title, func(t *testing.T) {
			start_signatory()
			defer stop_signatory()
			mkdir()
			if test.watermarkBefore != nil {
				write_watermark_file(test.watermarkBefore, test.chainID+".json")
			}
			defer remove_watermark_files()
			n := len(test.signRequestBodies)
			wg.Add(n)
			for i := 1; i <= n; i++ {
				go request_sign_concurrent(test.signRequestBodies[i-1])
			}
			wg.Wait()
			success := 0
			fail := 0
			for i, code := range codes {
				if code == 200 {
					success++
					require.Contains(t, res[i], "signature", "response should contain signature")
				} else {
					fail++
					require.Equal(t, test.expectedFailureCode, code)
					require.Contains(t, res[i], test.expectedFailureMessage, "unexpected failure message")
				}
			}
			require.Equal(t, test.expectedSuccessCount, success)
			require.Equal(t, test.expectedFailureCount, fail)
			b := read_watermark_file(test.chainID)
			var om operationMap
			dec := json.NewDecoder(bytes.NewReader(b))
			err := dec.Decode(&om)
			require.Nil(t, err)
			require.Equal(t, test.watermarkAfter["block"][pkh].Level, om["block"][pkh].Level)
			require.Equal(t, test.watermarkAfter["block"][pkh].Round, om["block"][pkh].Round)
		})
	}
}

func request_sign_concurrent(request string) {
	defer wg.Done()
	code, message := request_sign(request)
	mutex.Lock()
	{
		codes = append(codes, code)
		res = append(res, string(message))
	}
	mutex.Unlock()
}

func start_signatory() {
	_, err := exec.Command("docker", "compose", "-f", "./docker-compose.yml", "up", "-d", "--wait").CombinedOutput()
	if err != nil {
		log.Fatal("signatory container failed to start")
	}
}

func stop_signatory() {
	_, err := exec.Command("docker", "compose", "-f", "./docker-compose.yml", "down").CombinedOutput()
	if err != nil {
		log.Fatal("signatory container failed to stop")
	}
}

func mkdir() {
	_, err := exec.Command("docker", "exec", "signatory", "mkdir", "-p", "/var/lib/signatory/watermark").CombinedOutput()
	if err != nil {
		log.Fatal("failed to make watermark directory")
	}
}

func remove_watermark_files() {
	_, err := exec.Command("docker", "exec", "signatory", "rm", "-f", "/var/lib/signatory/watermark/*").CombinedOutput()
	if err != nil {
		log.Fatal("failed to remove watermark files")
	}
}

func write_watermark_file(om operationMap, filename string) {
	json, err := json.Marshal(om)
	if err != nil {
		log.Fatal("json marshal failed")
	}
	shell := "echo '" + string(json) + "' >/var/lib/signatory/watermark/" + filename
	_, err = exec.Command("docker", "exec", "signatory", "bash", "-c", shell).CombinedOutput()
	if err != nil {
		log.Fatal("failed to write watermark file")
	}
}

func read_watermark_file(chainId string) (out []byte) {
	out, err := exec.Command("docker", "exec", "signatory", "cat", "/var/lib/signatory/watermark/"+chainId+".json").CombinedOutput()
	if err != nil {
		log.Fatal("failed to read watermark file")
	}
	return
}

func request_sign(body string) (int, []byte) {
	reqbody := strings.NewReader(body)
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, url, reqbody)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(bytes))
	return resp.StatusCode, bytes
}
