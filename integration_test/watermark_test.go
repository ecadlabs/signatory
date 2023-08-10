package integrationtest

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"sync"
	"testing"

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

type functionalTestCase struct {
	title               string
	signRequestBodies   []string
	expectedStatusCodes []int
	expectedResponses   []any
	watermarkBefore     watermarkFile
	watermarkAfter      watermarkFile
	chainID             string
}

var functionalTestCases = []functionalTestCase{
	{title: "watermark file is created if it does not exist",
		signRequestBodies: []string{
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277ae404b7528bb55c532567eb5a866e2a9e7d4e120d2627b4cfb58061756071d6f4a5630000002500000001020000000400000002000000040000000000000004ffffffff0000000400000006080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad12000000003e9dad7a000000000002\"",
		},
		expectedStatusCodes: []int{200, 409},
		expectedResponses: []any{SignSuccessResponse{Signature: "edsigu6FPqZdPhLNo5AGCkdscaiMdZXsiV5djxy1v2r89J1ZWfVfZ2UXJEcURSsx38JSHXtccr9o5yzJ46NL6mGEZbZ86fiJjuv"},
			[]SignFailureResponse{{Id: "failure", Kind: "temporary", Msg: "watermark validation failed"}}},
		watermarkBefore: nil,
		watermarkAfter:  watermarkFile{pkh: {"block": {Level: 2, Round: 0, Hash: "vh2i6wpkn9bGpw47r3RhnfHiCrLvzTvQT36AmEZNPPsKqcN7yecT"}}},
		chainID:         "NetXo5iVw1vBoxM",
	},
	{title: "existing watermark file is honoured and updated",

		signRequestBodies: []string{
			"\"11b3d79f990000000701e6be95eec66c430c141a3bdd29f969b93e708ea1a9e12715ff8cb73ec206e1e70000000064277b2c040f461cefa3799f612ea7055449b42addee450a4a5269d983d6e3682c9f0d211500000021000000010200000004000000070000000000000004ffffffff000000040000000250ab35f1928fb750579a4785809eb9e95708e6701beacbc3f9ec93f4b93bfde7d1eba261c619f58322994e3093b15cd1a0b2253ee0d19b477d4842c53bcb3f4d00000002a40d1a28000000000002\"",
			"\"11b3d79f990000000701e6be95eec66c430c141a3bdd29f969b93e708ea1a9e12715ff8cb73ec206e1e70000000064277b5004e67efbd02ffea1e25925b7d385d4be010ba88ed58a782b91f619008d8f093eb60000002500000001020000000400000007000000040000000200000004ffffffff000000040000000550ab35f1928fb750579a4785809eb9e95708e6701beacbc3f9ec93f4b93bfde7d1eba261c619f58322994e3093b15cd1a0b2253ee0d19b477d4842c53bcb3f4d00000002a40d1a28000000000002\"",
		},
		expectedStatusCodes: []int{200, 409},
		expectedResponses: []any{SignSuccessResponse{Signature: "edsigtbYeDN9n2VjpoCmPVt5tQBe6Y95wTPPpgtVTx3g2S4hQSwypcdBWm5s6gfTi567MFFpDqXPRmdUBo4VqseLZdZc8LWnvK9"},
			[]SignFailureResponse{{Id: "failure", Kind: "temporary", Msg: "watermark validation failed"}}},
		watermarkBefore: watermarkFile{pkh: {"block": {Level: 6, Round: 0, Hash: "vh2i6wpkn9bGpw47r3RhnfHiCrLvzTvQT36AmEZNPPsKqcN7yecT"}}},
		watermarkAfter:  watermarkFile{pkh: {"block": {Level: 7, Round: 2, Hash: "vh2x7GpWVr8wSUE7HuAr5antYqgqzXFTDA4Wy6UUAMTzvNU1cnd4"}}},
		chainID:         "NetXo5iVw1vBoxM",
	},
	{title: "signing duplicate request is ok",

		signRequestBodies: []string{
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\"",
		},
		expectedStatusCodes: []int{200, 200},
		expectedResponses: []any{SignSuccessResponse{Signature: "edsigu6FPqZdPhLNo5AGCkdscaiMdZXsiV5djxy1v2r89J1ZWfVfZ2UXJEcURSsx38JSHXtccr9o5yzJ46NL6mGEZbZ86fiJjuv"},
			SignSuccessResponse{Signature: "edsigu6FPqZdPhLNo5AGCkdscaiMdZXsiV5djxy1v2r89J1ZWfVfZ2UXJEcURSsx38JSHXtccr9o5yzJ46NL6mGEZbZ86fiJjuv"}},
		watermarkBefore: nil,
		watermarkAfter:  watermarkFile{pkh: {"block": {Level: 2, Round: 0, Hash: "vh2i6wpkn9bGpw47r3RhnfHiCrLvzTvQT36AmEZNPPsKqcN7yecT"}}},
		chainID:         "NetXo5iVw1vBoxM",
	},
	{title: "level is more significant than round for successful signing",

		signRequestBodies: []string{
			"\"11b3d79f990000000701e6be95eec66c430c141a3bdd29f969b93e708ea1a9e12715ff8cb73ec206e1e70000000064277b2c040f461cefa3799f612ea7055449b42addee450a4a5269d983d6e3682c9f0d211500000021000000010200000004000000070000000000000004ffffffff000000040000000250ab35f1928fb750579a4785809eb9e95708e6701beacbc3f9ec93f4b93bfde7d1eba261c619f58322994e3093b15cd1a0b2253ee0d19b477d4842c53bcb3f4d00000002a40d1a28000000000002\"",
		},
		expectedStatusCodes: []int{200},
		expectedResponses:   []any{SignSuccessResponse{Signature: "edsigtbYeDN9n2VjpoCmPVt5tQBe6Y95wTPPpgtVTx3g2S4hQSwypcdBWm5s6gfTi567MFFpDqXPRmdUBo4VqseLZdZc8LWnvK9"}},
		watermarkBefore:     watermarkFile{pkh: {"block": {Level: 6, Round: 3, Hash: "vh2i6wpkn9bGpw47r3RhnfHiCrLvzTvQT36AmEZNPPsKqcN7yecT"}}},
		watermarkAfter:      watermarkFile{pkh: {"block": {Level: 7, Round: 2, Hash: "vh2x7GpWVr8wSUE7HuAr5antYqgqzXFTDA4Wy6UUAMTzvNU1cnd4"}}},
		chainID:             "NetXo5iVw1vBoxM",
	},
	{title: "level is more significant than round for identifying watermark",

		signRequestBodies: []string{
			"\"11b3d79f990000000701e6be95eec66c430c141a3bdd29f969b93e708ea1a9e12715ff8cb73ec206e1e70000000064277b2c040f461cefa3799f612ea7055449b42addee450a4a5269d983d6e3682c9f0d211500000021000000010200000004000000070000000000000004ffffffff000000040000000250ab35f1928fb750579a4785809eb9e95708e6701beacbc3f9ec93f4b93bfde7d1eba261c619f58322994e3093b15cd1a0b2253ee0d19b477d4842c53bcb3f4d00000002a40d1a28000000000002\"",
		},
		expectedStatusCodes: []int{409},
		expectedResponses:   []any{[]SignFailureResponse{{Id: "failure", Kind: "temporary", Msg: "watermark validation failed"}}},
		watermarkBefore:     watermarkFile{pkh: {"block": {Level: 8, Round: 1, Hash: "vh2i6wpkn9bGpw47r3RhnfHiCrLvzTvQT36AmEZNPPsKqcN7yecT"}}},
		watermarkAfter:      watermarkFile{pkh: {"block": {Level: 8, Round: 1, Hash: "vh2i6wpkn9bGpw47r3RhnfHiCrLvzTvQT36AmEZNPPsKqcN7yecT"}}},
		chainID:             "NetXo5iVw1vBoxM",
	},
	{title: "round is used for watermark if level is the same",

		signRequestBodies: []string{
			"\"11b3d79f990000000701e6be95eec66c430c141a3bdd29f969b93e708ea1a9e12715ff8cb73ec206e1e70000000064277b2c040f461cefa3799f612ea7055449b42addee450a4a5269d983d6e3682c9f0d211500000021000000010200000004000000070000000000000004ffffffff000000040000000250ab35f1928fb750579a4785809eb9e95708e6701beacbc3f9ec93f4b93bfde7d1eba261c619f58322994e3093b15cd1a0b2253ee0d19b477d4842c53bcb3f4d00000002a40d1a28000000000002\"",
		},
		expectedStatusCodes: []int{409},
		expectedResponses:   []any{[]SignFailureResponse{{Id: "failure", Kind: "temporary", Msg: "watermark validation failed"}}},
		watermarkBefore:     watermarkFile{pkh: {"block": {Level: 7, Round: 3, Hash: "vh2i6wpkn9bGpw47r3RhnfHiCrLvzTvQT36AmEZNPPsKqcN7yecT"}}},
		watermarkAfter:      watermarkFile{pkh: {"block": {Level: 7, Round: 3, Hash: "vh2i6wpkn9bGpw47r3RhnfHiCrLvzTvQT36AmEZNPPsKqcN7yecT"}}},
		chainID:             "NetXo5iVw1vBoxM",
	},
	{title: "baking happy path scenario - first sign block, then preendorsement, finally endorsement",

		signRequestBodies: []string{
			"\"11b3d79f99000000220181ff3a903959741b102d579148d3b1ea56ad7bc77e102def5cc73c49c062217a000000006427822b0480a2ea07609835343e53282a2e0d8ef20f54d6a7c1603d3874c2a2a7fceb3d3d00000021000000010200000004000000220000000000000004fffffffd000000040000000415b3aa8c735353cf4cde8aec00319d8922538fef77d44ee6780c8872bf63408bfd5a576ce08fa0e87e7b41d373d04a2df8798b234c7a4f8483a1d839e0066c0600000004a40d1a28000000000002\"",
			"\"12b3d79f9981ff3a903959741b102d579148d3b1ea56ad7bc77e102def5cc73c49c062217a1400040000002200000004fd5a576ce08fa0e87e7b41d373d04a2df8798b234c7a4f8483a1d839e0066c06\"",
			"\"13b3d79f9981ff3a903959741b102d579148d3b1ea56ad7bc77e102def5cc73c49c062217a1500040000002200000004fd5a576ce08fa0e87e7b41d373d04a2df8798b234c7a4f8483a1d839e0066c06\"",
		},
		expectedStatusCodes: []int{200, 200, 200},
		expectedResponses: []any{SignSuccessResponse{Signature: "edsigtfHHgiTKBhZ4wzfZwCtLpWsS1q4pHR47YbhWHLzxmx95LpSQQXXC4nWhoHCp7ppEeC2eHw2Be7zjQrKwHvsmb8KyJcGf1b"},
			SignSuccessResponse{Signature: "edsigtjpdXbicHctbhx82tQKMYNFrwSimTkFj16iWo38jMSFB9gzxbyyAuKmX8detwLGp8CWDvHyFs5pcivpCSHrJVD4ZUWSb5r"},
			SignSuccessResponse{Signature: "edsigtfoBKBjfYYASaf194oQknF3r5eag81ihkErSSi1WPiV6qfrQjCFWomAbjG63PKaLoUvoNxqK4TCD4MLoJAFC6JtHwtBYYn"}},
		watermarkBefore: watermarkFile{pkh: {"block": {Level: 33, Round: 2, Hash: "vh2i6wpkn9bGpw47r3RhnfHiCrLvzTvQT36AmEZNPPsKqcN7yecT"}}},
		watermarkAfter: watermarkFile{pkh: {"block": {Level: 34, Round: 4, Hash: "vh2E3QPN8R55XtdeZXsPtbgXErMeLcE5YbjDMcUzXsFByL97u5Qc"},
			"endorsement":    {Level: 34, Round: 4, Hash: "vh216VxjGyVK2XWEQ5gyFcAMLEqPzRKJijB6ZUybZjnwetdZp8Lm"},
			"preendorsement": {Level: 34, Round: 4, Hash: "vh2KHE9afrJBSzLQcnP21cCtHfc9yPsjCVzsbBfLTpzRTenXtp1s"}}},
		chainID: "NetXo5iVw1vBoxM",
	},
	{title: "baking scenario - block request can arrive last",

		signRequestBodies: []string{
			"\"12b3d79f9981ff3a903959741b102d579148d3b1ea56ad7bc77e102def5cc73c49c062217a1400040000002200000004fd5a576ce08fa0e87e7b41d373d04a2df8798b234c7a4f8483a1d839e0066c06\"",
			"\"13b3d79f9981ff3a903959741b102d579148d3b1ea56ad7bc77e102def5cc73c49c062217a1500040000002200000004fd5a576ce08fa0e87e7b41d373d04a2df8798b234c7a4f8483a1d839e0066c06\"",
			"\"11b3d79f99000000220181ff3a903959741b102d579148d3b1ea56ad7bc77e102def5cc73c49c062217a000000006427822b0480a2ea07609835343e53282a2e0d8ef20f54d6a7c1603d3874c2a2a7fceb3d3d00000021000000010200000004000000220000000000000004fffffffd000000040000000415b3aa8c735353cf4cde8aec00319d8922538fef77d44ee6780c8872bf63408bfd5a576ce08fa0e87e7b41d373d04a2df8798b234c7a4f8483a1d839e0066c0600000004a40d1a28000000000002\"",
		},
		expectedStatusCodes: []int{200, 200, 200},
		expectedResponses: []any{SignSuccessResponse{Signature: "edsigtjpdXbicHctbhx82tQKMYNFrwSimTkFj16iWo38jMSFB9gzxbyyAuKmX8detwLGp8CWDvHyFs5pcivpCSHrJVD4ZUWSb5r"},
			SignSuccessResponse{Signature: "edsigtfoBKBjfYYASaf194oQknF3r5eag81ihkErSSi1WPiV6qfrQjCFWomAbjG63PKaLoUvoNxqK4TCD4MLoJAFC6JtHwtBYYn"},
			SignSuccessResponse{Signature: "edsigtfHHgiTKBhZ4wzfZwCtLpWsS1q4pHR47YbhWHLzxmx95LpSQQXXC4nWhoHCp7ppEeC2eHw2Be7zjQrKwHvsmb8KyJcGf1b"}},
		watermarkBefore: watermarkFile{pkh: {"block": {Level: 33, Round: 2, Hash: "vh2i6wpkn9bGpw47r3RhnfHiCrLvzTvQT36AmEZNPPsKqcN7yecT"}}},
		watermarkAfter: watermarkFile{pkh: {"block": {Level: 34, Round: 4, Hash: "vh2E3QPN8R55XtdeZXsPtbgXErMeLcE5YbjDMcUzXsFByL97u5Qc"},
			"endorsement":    {Level: 34, Round: 4, Hash: "vh216VxjGyVK2XWEQ5gyFcAMLEqPzRKJijB6ZUybZjnwetdZp8Lm"},
			"preendorsement": {Level: 34, Round: 4, Hash: "vh2KHE9afrJBSzLQcnP21cCtHfc9yPsjCVzsbBfLTpzRTenXtp1s"}}},
		chainID: "NetXo5iVw1vBoxM",
	},
}

func TestWatermark(t *testing.T) {
	for _, test := range functionalTestCases {
		remove_watermark_files()
		restart_signatory()
		t.Run(test.title, func(t *testing.T) {
			if test.watermarkBefore != nil {
				mkdir()
				write_watermark_file(test.watermarkBefore, test.chainID+".json")
				restart_signatory()
			}
			for i, request := range test.signRequestBodies {
				code, message := RequestSignature(pkh, request)
				require.Equal(t, test.expectedStatusCodes[i], code)
				if code == 200 {
					var sr SignSuccessResponse
					dec := json.NewDecoder(bytes.NewReader(message))
					err := dec.Decode(&sr)
					require.Nil(t, err)
					assert.Equal(t, test.expectedResponses[i], sr)
				} else {
					var fr []SignFailureResponse
					dec := json.NewDecoder(bytes.NewReader(message))
					err := dec.Decode(&fr)
					require.Nil(t, err)
					assert.Equal(t, test.expectedResponses[i], fr)
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
	restart_signatory()
}

type concurrencyTestCase struct {
	title                  string
	description            string
	signRequestBodies      []string
	expectedSuccessCount   int
	expectedFailureCount   int
	expectedFailureCode    int
	expectedFailureMessage string
	watermarkBefore        watermarkFile
	watermarkAfter         watermarkFile
	chainID                string
}

var concurrencyTestCases = []concurrencyTestCase{
	{title: "10 concurrent, 2 distinct, requests, requesting double sign block level 2 round 0, no existing watermark",
		description: "this is a stress test to ensure that watermark file is not corrupted by concurrent requests",
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
		expectedFailureMessage: "watermark validation failed",
		expectedFailureCode:    409,
		watermarkBefore:        nil,
		watermarkAfter:         watermarkFile{pkh: {"block": {Level: 2, Round: 0, Hash: "unknown_not_verfied"}}},
		chainID:                "NetXo5iVw1vBoxM",
	},
}

var (
	mutex sync.Mutex
	wg    sync.WaitGroup
	res   []string
	codes []int
)

func TestWatermarkConcurrency(t *testing.T) {
	for _, test := range concurrencyTestCases {
		remove_watermark_files()
		restart_signatory()
		t.Run(test.title, func(t *testing.T) {
			mkdir()
			if test.watermarkBefore != nil {
				write_watermark_file(test.watermarkBefore, test.chainID+".json")
				restart_signatory()
			}
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
			var wf watermarkFile
			dec := json.NewDecoder(bytes.NewReader(b))
			err := dec.Decode(&wf)
			require.Nil(t, err)
			require.Equal(t, test.watermarkAfter[pkh]["block"].Level, wf[pkh]["block"].Level)
			require.Equal(t, test.watermarkAfter[pkh]["block"].Round, wf[pkh]["block"].Round)
		})
	}
	remove_watermark_files()
	restart_signatory()
}

func request_sign_concurrent(request string) {
	defer wg.Done()
	code, message := RequestSignature(pkh, request)
	mutex.Lock()
	{
		codes = append(codes, code)
		res = append(res, string(message))
	}
	mutex.Unlock()
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
