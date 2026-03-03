package server_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"sync"
	"testing"

	"github.com/ecadlabs/gotez/v2/crypt"
	integrationtest "github.com/ecadlabs/signatory/integration_test/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type watermarkFile map[string]map[string]*watermarkData
type watermarkData struct {
	Round int32  `json:"round,omitempty"`
	Level int32  `json:"level"`
	Hash  string `json:"hash"`
}

const (
	protocol  = "http://"
	host      = "localhost"
	port      = "6732"
	pkh       = "tz1WGcYos3hL7GXYXjKrMnSFdkT7FyXnFBvf"
	url       = protocol + host + ":" + port + "/keys/" + pkh
	dir       = "/var/lib/signatory/watermark_v2/"
	container = "signatory"
)

// Payloads generated from mainnet blocks 12180920-12180922 using cmd/gen-test-payloads.
// Sandbox chain_id (NetXo5iVw1vBoxM) is used because integration tests run against a sandbox.
const (
	// A1: block level=2, fitness_round=0, payload_round=0 (fields from mainnet 12180922)
	payloadA1 = "\"11b3d79f990000000218954ac461a1b7642a78880e485b1db8da1e96f6cac6ee7dae541c7b6a8e66840b0000000069a8c3a3043c218c11c12df01faa1113bb827d7de00cc6f95993e220901ca35ff0cec5954000000021000000010200000004000000020000000000000004ffffffff0000000400000000ecbf5c99c96392b252bb846394c12c422e0cb2e050aa018dcc2a880f9c9c636858335430566f4b95401c110f33e74d3a324f83ad6003ed9d5e93ce617fa11e4400000000d7d4b0aea9d000000000\""

	// A2: block level=2, fitness_round=0, payload_round=0 (fields from mainnet 12180921; double-bake with A1)
	payloadA2 = "\"11b3d79f990000000218e790bc8332da94dfdf97b041d5fb918500d56e3647125732b737da8dcf1aa4040000000069a8c39d0429599f0c1222b23808083de0b51e47ea45f2cd3e916dcdd5bd5fdbc7ef5c2c3b00000021000000010200000004000000020000000000000004ffffffff00000004000000007cf2ed78325f41df290d68f691c691c976107148beae12495d946a419750ab7b03f9321cbf1a85d7701522fae4938181944dc8b746ef4e8f85260f528bfa1a2c000000005a3ca147d36b02000000\""

	// B1: block level=7, fitness_round=2, payload_round=2 (fields from mainnet 12180920)
	payloadB1 = "\"11b3d79f9900000007184572152267169504aff4d7cb486684d7e36ffed77523565eb2981d05f00f95520000000069a8c397042b9ee182b36afeb571d6d7218853177fff8d2aca0738eaf9a32284eb932bca3500000021000000010200000004000000070000000000000004ffffffff0000000400000002be32a3976c093ad2a4ce5168b38e0756589b740ca2477fc07c5fa52f55c241f222497e0fc752e228440e90f23f104c8de0aec6b5c502dfbfe8e5e21857bacf01000000025a3ca147680601000000\""

	// B2: block level=7, fitness_round=2, payload_round=2 (fields from mainnet 12180921; double-bake with B1)
	payloadB2 = "\"11b3d79f990000000718e790bc8332da94dfdf97b041d5fb918500d56e3647125732b737da8dcf1aa4040000000069a8c39d0429599f0c1222b23808083de0b51e47ea45f2cd3e916dcdd5bd5fdbc7ef5c2c3b00000021000000010200000004000000070000000000000004ffffffff00000004000000027cf2ed78325f41df290d68f691c691c976107148beae12495d946a419750ab7b03f9321cbf1a85d7701522fae4938181944dc8b746ef4e8f85260f528bfa1a2c000000025a3ca147d36b02000000\""

	// C1: block level=34, fitness_round=4, payload_round=4 (fields from mainnet 12180922)
	payloadC1 = "\"11b3d79f990000002218954ac461a1b7642a78880e485b1db8da1e96f6cac6ee7dae541c7b6a8e66840b0000000069a8c3a3043c218c11c12df01faa1113bb827d7de00cc6f95993e220901ca35ff0cec5954000000021000000010200000004000000220000000000000004ffffffff0000000400000004ecbf5c99c96392b252bb846394c12c422e0cb2e050aa018dcc2a880f9c9c636858335430566f4b95401c110f33e74d3a324f83ad6003ed9d5e93ce617fa11e4400000004d7d4b0aea9d000000000\""

	// C2: preattestation level=34, round=4, slot=20 (branch from mainnet 12180922 hash)
	payloadC2 = "\"12b3d79f993222f293d2f293230ec36b0bef1caead619f1a7206ff54a0c198f07ae25bb151140014000000220000000458335430566f4b95401c110f33e74d3a324f83ad6003ed9d5e93ce617fa11e44\""

	// C3: attestation level=34, round=4, slot=21 (branch from mainnet 12180922 hash)
	payloadC3 = "\"13b3d79f993222f293d2f293230ec36b0bef1caead619f1a7206ff54a0c198f07ae25bb151150015000000220000000458335430566f4b95401c110f33e74d3a324f83ad6003ed9d5e93ce617fa11e44\""

	// Watermark hashes (blake2b-256 of encoded sign request, base58check with vh prefix)
	hashA1 = "vh2THNfr1pU3TjJyJkw7BKq19suqMX1W9PXRVAgpueELhGTAuhSx"
	hashA2 = "vh2ywY7jYH9vyATb8HJ1JGjPwyawULZ9q8PXXritQ2Bjseb15wcr"
	hashB1 = "vh2LsbNPiuNja766Mzq1DXd7kMAhF358snWJHhK9XPG6F5dSmXPn"
	hashC1 = "vh2QmrcNURnrNwT5HEJv6ZA8n2gfw1MzThoBHK7dgyJsjHmVJhvj"
	hashC2 = "vh1mTiEJuJiyimZf5sctgbnHBTLFthMVRNbiViYpLDMGK79TzUwB"
	hashC3 = "vh2UEcdXfsAWcTP1omYSp1q54H5S2x3zqfr2YqAcZ2Neyjauix1K"
)

type functionalTestCase struct {
	title               string
	signRequestBodies   []string
	expectedStatusCodes []int
	watermarkBefore     watermarkFile
	watermarkAfter      watermarkFile
	chainID             string
}

var functionalTestCases = []functionalTestCase{
	{title: "watermark file is created if it does not exist",
		signRequestBodies:   []string{payloadA1, payloadA2},
		expectedStatusCodes: []int{200, 409},
		watermarkBefore:     nil,
		watermarkAfter:      watermarkFile{pkh: {"block": {Level: 2, Round: 0, Hash: hashA1}}},
		chainID:             "NetXo5iVw1vBoxM",
	},
	{title: "existing watermark file is honoured and updated",
		signRequestBodies:   []string{payloadB1, payloadB2},
		expectedStatusCodes: []int{200, 409},
		watermarkBefore:     watermarkFile{pkh: {"block": {Level: 6, Round: 0, Hash: hashA1}}},
		watermarkAfter:      watermarkFile{pkh: {"block": {Level: 7, Round: 2, Hash: hashB1}}},
		chainID:             "NetXo5iVw1vBoxM",
	},
	{title: "signing duplicate request is ok",
		signRequestBodies:   []string{payloadA1, payloadA1},
		expectedStatusCodes: []int{200, 200},
		watermarkBefore:     nil,
		watermarkAfter:      watermarkFile{pkh: {"block": {Level: 2, Round: 0, Hash: hashA1}}},
		chainID:             "NetXo5iVw1vBoxM",
	},
	{title: "level is more significant than round for successful signing",
		signRequestBodies:   []string{payloadB1},
		expectedStatusCodes: []int{200},
		watermarkBefore:     watermarkFile{pkh: {"block": {Level: 6, Round: 3, Hash: hashA1}}},
		watermarkAfter:      watermarkFile{pkh: {"block": {Level: 7, Round: 2, Hash: hashB1}}},
		chainID:             "NetXo5iVw1vBoxM",
	},
	{title: "level is more significant than round for identifying watermark",
		signRequestBodies:   []string{payloadB1},
		expectedStatusCodes: []int{409},
		watermarkBefore:     watermarkFile{pkh: {"block": {Level: 8, Round: 1, Hash: hashA1}}},
		watermarkAfter:      watermarkFile{pkh: {"block": {Level: 8, Round: 1, Hash: hashA1}}},
		chainID:             "NetXo5iVw1vBoxM",
	},
	{title: "round is used for watermark if level is the same",
		signRequestBodies:   []string{payloadB1},
		expectedStatusCodes: []int{409},
		watermarkBefore:     watermarkFile{pkh: {"block": {Level: 7, Round: 3, Hash: hashA1}}},
		watermarkAfter:      watermarkFile{pkh: {"block": {Level: 7, Round: 3, Hash: hashA1}}},
		chainID:             "NetXo5iVw1vBoxM",
	},
	{title: "baking happy path scenario - first sign block, then preattestation, finally attestation",
		signRequestBodies:   []string{payloadC1, payloadC2, payloadC3},
		expectedStatusCodes: []int{200, 200, 200},
		watermarkBefore:     watermarkFile{pkh: {"block": {Level: 33, Round: 2, Hash: hashA1}}},
		watermarkAfter: watermarkFile{pkh: {"block": {Level: 34, Round: 4, Hash: hashC1},
			"preattestation": {Level: 34, Round: 4, Hash: hashC2},
			"attestation":    {Level: 34, Round: 4, Hash: hashC3}}},
		chainID: "NetXo5iVw1vBoxM",
	},
	{title: "baking scenario - block request can arrive last",
		signRequestBodies:   []string{payloadC2, payloadC3, payloadC1},
		expectedStatusCodes: []int{200, 200, 200},
		watermarkBefore:     watermarkFile{pkh: {"block": {Level: 33, Round: 2, Hash: hashA1}}},
		watermarkAfter: watermarkFile{pkh: {"block": {Level: 34, Round: 4, Hash: hashC1},
			"preattestation": {Level: 34, Round: 4, Hash: hashC2},
			"attestation":    {Level: 34, Round: 4, Hash: hashC3}}},
		chainID: "NetXo5iVw1vBoxM",
	},
}

var expectedFailureResponse = []integrationtest.SignFailureResponse{{Id: "failure", Kind: "temporary", Msg: "watermark validation failed"}}

func TestWatermark(t *testing.T) {
	for _, test := range functionalTestCases {
		remove_watermark_files()
		integrationtest.Restart_signatory()
		t.Run(test.title, func(t *testing.T) {
			if test.watermarkBefore != nil {
				mkdir()
				write_watermark_file(test.watermarkBefore, test.chainID+".json")
				integrationtest.Restart_signatory()
			}
			for i, request := range test.signRequestBodies {
				code, message := integrationtest.RequestSignature(pkh, request)
				require.Equal(t, test.expectedStatusCodes[i], code)
				if code == 200 {
					var sr integrationtest.SignSuccessResponse
					dec := json.NewDecoder(bytes.NewReader(message))
					err := dec.Decode(&sr)
					require.Nil(t, err)
					assert.NotEmpty(t, sr.Signature, "response should contain a non-empty signature")
					assertSignatureValid(t, request, sr.Signature)
				} else {
					var fr []integrationtest.SignFailureResponse
					dec := json.NewDecoder(bytes.NewReader(message))
					err := dec.Decode(&fr)
					require.Nil(t, err)
					assert.Equal(t, expectedFailureResponse, fr)
				}
			}
			b := read_watermark_file(test.chainID)
			var wf watermarkFile
			dec := json.NewDecoder(bytes.NewReader(b))
			err := dec.Decode(&wf)
			require.Nil(t, err)
			assert.Equal(t, test.watermarkAfter, wf)
		})
	}
	remove_watermark_files()
	integrationtest.Restart_signatory()
}

type concurrencyTestCase struct {
	title                 string
	description           string
	signRequestBodies     []string
	expectedSuccessCount  int
	expectedFailureCount  int
	expectedWinningHashes []string
	watermarkBefore       watermarkFile
	watermarkAfter        watermarkFile
	chainID               string
}

var concurrencyTestCases = []concurrencyTestCase{
	{title: "10 concurrent, 2 distinct, requests, requesting double sign block level 2 round 0, no existing watermark",
		description: "this is a stress test to ensure that watermark file is not corrupted by concurrent requests",
		signRequestBodies: []string{
			payloadA1, payloadA2,
			payloadA1, payloadA2,
			payloadA1, payloadA2,
			payloadA1, payloadA2,
			payloadA1, payloadA2,
		},
		expectedSuccessCount:  5,
		expectedFailureCount:  5,
		expectedWinningHashes: []string{hashA1, hashA2},
		watermarkBefore:       nil,
		watermarkAfter:        watermarkFile{pkh: {"block": {Level: 2, Round: 0}}},
		chainID:               "NetXo5iVw1vBoxM",
	},
}

func TestWatermarkConcurrency(t *testing.T) {
	type concurrencyResult struct {
		request string
		code    int
		message []byte
	}
	for _, test := range concurrencyTestCases {
		remove_watermark_files()
		integrationtest.Restart_signatory()
		t.Run(test.title, func(t *testing.T) {
			mkdir()
			if test.watermarkBefore != nil {
				write_watermark_file(test.watermarkBefore, test.chainID+".json")
				integrationtest.Restart_signatory()
			}
			n := len(test.signRequestBodies)
			results := make([]concurrencyResult, 0, n)
			var resultMtx sync.Mutex
			var wg sync.WaitGroup
			wg.Add(n)
			for i := range test.signRequestBodies {
				request := test.signRequestBodies[i]
				go func() {
					defer wg.Done()
					code, message := integrationtest.RequestSignature(pkh, request)
					resultMtx.Lock()
					results = append(results, concurrencyResult{request: request, code: code, message: message})
					resultMtx.Unlock()
				}()
			}
			wg.Wait()
			require.Len(t, results, n)
			success := 0
			fail := 0
			for _, result := range results {
				if result.code == 200 {
					success++
					var sr integrationtest.SignSuccessResponse
					err := json.NewDecoder(bytes.NewReader(result.message)).Decode(&sr)
					require.NoError(t, err)
					require.NotEmpty(t, sr.Signature, "response should contain signature")
					assertSignatureValid(t, result.request, sr.Signature)
				} else {
					fail++
					require.Equal(t, 409, result.code)
					var fr []integrationtest.SignFailureResponse
					err := json.NewDecoder(bytes.NewReader(result.message)).Decode(&fr)
					require.NoError(t, err)
					require.Equal(t, expectedFailureResponse, fr)
				}
			}
			require.Equal(t, test.expectedSuccessCount, success)
			require.Equal(t, test.expectedFailureCount, fail)
			b := read_watermark_file(test.chainID)
			var wf watermarkFile
			dec := json.NewDecoder(bytes.NewReader(b))
			err := dec.Decode(&wf)
			require.Nil(t, err)
			require.Equal(t, test.watermarkAfter[pkh]["block"].Level, wf[pkh]["block"].Level)
			require.Equal(t, test.watermarkAfter[pkh]["block"].Round, wf[pkh]["block"].Round)
			require.Contains(t, test.expectedWinningHashes, wf[pkh]["block"].Hash)
		})
	}
	remove_watermark_files()
	integrationtest.Restart_signatory()
}

func mkdir() {
	_, err := exec.Command("docker", "exec", container, "mkdir", "-p", dir).CombinedOutput()
	if err != nil {
		panic("failed to make watermark directory")
	}
}

func remove_watermark_files() {
	out, err := exec.Command("docker", "exec", container, "rm", "-rf", dir).CombinedOutput()
	if err != nil {
		panic("failed to remove watermark files: " + err.Error() + " " + string(out))
	}
}

func write_watermark_file(wf watermarkFile, filename string) {
	json, err := json.Marshal(wf)
	if err != nil {
		panic("json marshal failed")
	}
	shell := "echo '" + string(json) + "' >" + dir + filename
	_, err = exec.Command("docker", "exec", container, "bash", "-c", shell).CombinedOutput()
	if err != nil {
		panic("failed to write watermark file")
	}
}

func read_watermark_file(chainId string) (out []byte) {
	out, err := exec.Command("docker", "exec", container, "cat", dir+chainId+".json").CombinedOutput()
	if err != nil {
		panic("failed to read watermark file")
	}
	return
}

func assertSignatureValid(t *testing.T, requestBody, signature string) {
	t.Helper()

	decodedRequest, err := decodeSignRequestBody(requestBody)
	require.NoError(t, err)

	pubKey, err := crypt.ParsePublicKey([]byte(integrationtest.GetPublicKey(pkh)))
	require.NoError(t, err)

	sig, err := crypt.ParseSignature([]byte(signature))
	require.NoError(t, err)

	assert.True(t, sig.Verify(pubKey, decodedRequest), "response signature is not valid for request payload")
}

func decodeSignRequestBody(body string) ([]byte, error) {
	var payloadHex string
	if err := json.Unmarshal([]byte(body), &payloadHex); err != nil {
		return nil, err
	}
	return hex.DecodeString(payloadHex)
}
