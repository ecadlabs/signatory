package componenttest

import (
	"bytes"
	"encoding/json"
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
	protocol  = "http://"
	host      = "localhost"
	port      = "6732"
	pkh       = "tz1WGcYos3hL7GXYXjKrMnSFdkT7FyXnFBvf"
	url       = protocol + host + ":" + port + "/keys/" + pkh
	dir       = "/var/lib/signatory/watermark/"
	container = "signatory"
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
	{title: "watermark file is created if it does not exist",
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
	{title: "existing watermark file is honoured and updated",
		signRequestBodies: []string{
			"\"11b3d79f990000000701e6be95eec66c430c141a3bdd29f969b93e708ea1a9e12715ff8cb73ec206e1e70000000064277b2c040f461cefa3799f612ea7055449b42addee450a4a5269d983d6e3682c9f0d211500000021000000010200000004000000070000000000000004ffffffff000000040000000250ab35f1928fb750579a4785809eb9e95708e6701beacbc3f9ec93f4b93bfde7d1eba261c619f58322994e3093b15cd1a0b2253ee0d19b477d4842c53bcb3f4d00000002a40d1a28000000000002\"",
			"\"11b3d79f990000000701e6be95eec66c430c141a3bdd29f969b93e708ea1a9e12715ff8cb73ec206e1e70000000064277b5004e67efbd02ffea1e25925b7d385d4be010ba88ed58a782b91f619008d8f093eb60000002500000001020000000400000007000000040000000200000004ffffffff000000040000000550ab35f1928fb750579a4785809eb9e95708e6701beacbc3f9ec93f4b93bfde7d1eba261c619f58322994e3093b15cd1a0b2253ee0d19b477d4842c53bcb3f4d00000002a40d1a28000000000002\"",
		},
		expectedStatusCodes: []int{200, 409},
		expectedResponses: []any{SuccessResponse{Signature: "sigRjB6JvskZYnk1n6MrEhStMamK11UkXEKCjjDhg3RigT983E7jGRg2dBe4quycvzoiLbv1c4w1WR4GTeDVzbSWY2PH6Kok"},
			[]FailureResponse{{Id: "failure", Kind: "temporary", Msg: "block level 7 and round 2 already signed with different data"}}},
		watermarkBefore: operationMap{"block": {pkh: {Level: 6, Hash: "vh3RyrssDP79J84CiJurBBeEqfGYpPvnscaeyvq2Uzdoh6DDyb26", Round: 0}}},
		watermarkAfter:  operationMap{"block": {pkh: {Level: 7, Hash: "vh2x7GpWVr8wSUE7HuAr5antYqgqzXFTDA4Wy6UUAMTzvNU1cnd4", Round: 2}}},
		chainID:         "NetXo5iVw1vBoxM",
	},
	{title: "signing duplicate request is ok",
		signRequestBodies: []string{
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\"",
			"\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\"",
		},
		expectedStatusCodes: []int{200, 200},
		expectedResponses: []any{SuccessResponse{Signature: "sigvRviWQVRQBm1yGucc2RdR57nhnnWSm9bHGBJW8AHfYZMfixXacD9ZEWQHLF2qFw6M8zve1j9NLHMaHu77tbQW3zk46UNL"},
			SuccessResponse{Signature: "sigvRviWQVRQBm1yGucc2RdR57nhnnWSm9bHGBJW8AHfYZMfixXacD9ZEWQHLF2qFw6M8zve1j9NLHMaHu77tbQW3zk46UNL"}},
		watermarkBefore: nil,
		watermarkAfter:  operationMap{"block": {pkh: {Level: 2, Hash: "vh2i6wpkn9bGpw47r3RhnfHiCrLvzTvQT36AmEZNPPsKqcN7yecT", Round: 0}}},
		chainID:         "NetXo5iVw1vBoxM",
	},
	{title: "level is more significant than round for successful signing",
		signRequestBodies: []string{
			"\"11b3d79f990000000701e6be95eec66c430c141a3bdd29f969b93e708ea1a9e12715ff8cb73ec206e1e70000000064277b2c040f461cefa3799f612ea7055449b42addee450a4a5269d983d6e3682c9f0d211500000021000000010200000004000000070000000000000004ffffffff000000040000000250ab35f1928fb750579a4785809eb9e95708e6701beacbc3f9ec93f4b93bfde7d1eba261c619f58322994e3093b15cd1a0b2253ee0d19b477d4842c53bcb3f4d00000002a40d1a28000000000002\"",
		},
		expectedStatusCodes: []int{200},
		expectedResponses:   []any{SuccessResponse{Signature: "sigRjB6JvskZYnk1n6MrEhStMamK11UkXEKCjjDhg3RigT983E7jGRg2dBe4quycvzoiLbv1c4w1WR4GTeDVzbSWY2PH6Kok"}},
		watermarkBefore:     operationMap{"block": {pkh: {Level: 6, Hash: "vh3RyrssDP79J84CiJurBBeEqfGYpPvnscaeyvq2Uzdoh6DDyb26", Round: 3}}},
		watermarkAfter:      operationMap{"block": {pkh: {Level: 7, Hash: "vh2x7GpWVr8wSUE7HuAr5antYqgqzXFTDA4Wy6UUAMTzvNU1cnd4", Round: 2}}},
		chainID:             "NetXo5iVw1vBoxM",
	},
	{title: "level is more significant than round for identifying watermark",
		signRequestBodies: []string{
			"\"11b3d79f990000000701e6be95eec66c430c141a3bdd29f969b93e708ea1a9e12715ff8cb73ec206e1e70000000064277b2c040f461cefa3799f612ea7055449b42addee450a4a5269d983d6e3682c9f0d211500000021000000010200000004000000070000000000000004ffffffff000000040000000250ab35f1928fb750579a4785809eb9e95708e6701beacbc3f9ec93f4b93bfde7d1eba261c619f58322994e3093b15cd1a0b2253ee0d19b477d4842c53bcb3f4d00000002a40d1a28000000000002\"",
		},
		expectedStatusCodes: []int{409},
		expectedResponses:   []any{[]FailureResponse{{Id: "failure", Kind: "temporary", Msg: "block level 7 not above high watermark 8"}}},
		watermarkBefore:     operationMap{"block": {pkh: {Level: 8, Hash: "vh3RyrssDP79J84CiJurBBeEqfGYpPvnscaeyvq2Uzdoh6DDyb26", Round: 1}}},
		watermarkAfter:      operationMap{"block": {pkh: {Level: 8, Hash: "vh3RyrssDP79J84CiJurBBeEqfGYpPvnscaeyvq2Uzdoh6DDyb26", Round: 1}}},
		chainID:             "NetXo5iVw1vBoxM",
	},
	{title: "round is used for watermark if level is the same",
		signRequestBodies: []string{
			"\"11b3d79f990000000701e6be95eec66c430c141a3bdd29f969b93e708ea1a9e12715ff8cb73ec206e1e70000000064277b2c040f461cefa3799f612ea7055449b42addee450a4a5269d983d6e3682c9f0d211500000021000000010200000004000000070000000000000004ffffffff000000040000000250ab35f1928fb750579a4785809eb9e95708e6701beacbc3f9ec93f4b93bfde7d1eba261c619f58322994e3093b15cd1a0b2253ee0d19b477d4842c53bcb3f4d00000002a40d1a28000000000002\"",
		},
		expectedStatusCodes: []int{409},
		expectedResponses:   []any{[]FailureResponse{{Id: "failure", Kind: "temporary", Msg: "block level 7 and round 2 not above high watermark (7,3)"}}},
		watermarkBefore:     operationMap{"block": {pkh: {Level: 7, Hash: "vh3RyrssDP79J84CiJurBBeEqfGYpPvnscaeyvq2Uzdoh6DDyb26", Round: 3}}},
		watermarkAfter:      operationMap{"block": {pkh: {Level: 7, Hash: "vh3RyrssDP79J84CiJurBBeEqfGYpPvnscaeyvq2Uzdoh6DDyb26", Round: 3}}},
		chainID:             "NetXo5iVw1vBoxM",
	},
	{title: "baking happy path scenario - first sign block, then preendorsement, finally endorsement",
		signRequestBodies: []string{
			"\"11b3d79f99000000220181ff3a903959741b102d579148d3b1ea56ad7bc77e102def5cc73c49c062217a000000006427822b0480a2ea07609835343e53282a2e0d8ef20f54d6a7c1603d3874c2a2a7fceb3d3d00000021000000010200000004000000220000000000000004fffffffd000000040000000415b3aa8c735353cf4cde8aec00319d8922538fef77d44ee6780c8872bf63408bfd5a576ce08fa0e87e7b41d373d04a2df8798b234c7a4f8483a1d839e0066c0600000004a40d1a28000000000002\"",
			"\"12b3d79f9981ff3a903959741b102d579148d3b1ea56ad7bc77e102def5cc73c49c062217a1400040000002200000004fd5a576ce08fa0e87e7b41d373d04a2df8798b234c7a4f8483a1d839e0066c06\"",
			"\"13b3d79f9981ff3a903959741b102d579148d3b1ea56ad7bc77e102def5cc73c49c062217a1500040000002200000004fd5a576ce08fa0e87e7b41d373d04a2df8798b234c7a4f8483a1d839e0066c06\"",
		},
		expectedStatusCodes: []int{200, 200, 200},
		expectedResponses: []any{SuccessResponse{Signature: "sigVTpZfEQumN2togGoB39sDavEzytJnBXAuwmYzzymc882zVoudc6yjGnkgb22MdtCeZ2NREpoW2xg4HjdnXoQ5FsLo6MYR"},
			SuccessResponse{Signature: "siga1AQYVi1ghZem8jkNUAb4yMAcdqV7P8dQxn4h8kM6EDqs4N7645pGXc6336qs6Tgf2bznBu2Trqz8mzn9WLJ9zTZsiyLw"},
			SuccessResponse{Signature: "sigVyiC8WmGbyQXU1qvmZZpwmLJpVk9Nr7NZ6hiN1XPNU9XqupEJLRihvggfUFHrPzMwTBTT3xDqESKZJbe1uDuFpBzUm1hZ"}},
		watermarkBefore: operationMap{"block": {pkh: {Level: 33, Hash: "vh2DhMVAsCB8C6HxZ4PWqgtJYgb9ddojcjy99dHv131ADW9N91jf", Round: 2}},
			"preendorsement": {pkh: {Level: 33, Hash: "vh1zCCBsR6djpWb4ad5RsAyGnvXUUGza9QfoeMM1VaUsMwfdKXUq", Round: 2}},
			"endorsement":    {pkh: {Level: 33, Hash: "vh3RUn3hLiQFRakQdr8X2wegKyTmGZYqQmf9Nmg5ez4ngUqHwKUR", Round: 2}}},
		watermarkAfter: operationMap{"block": {pkh: {Level: 34, Hash: "vh2E3QPN8R55XtdeZXsPtbgXErMeLcE5YbjDMcUzXsFByL97u5Qc", Round: 4}},
			"preendorsement": {pkh: {Level: 34, Hash: "vh2KHE9afrJBSzLQcnP21cCtHfc9yPsjCVzsbBfLTpzRTenXtp1s", Round: 4}},
			"endorsement":    {pkh: {Level: 34, Hash: "vh216VxjGyVK2XWEQ5gyFcAMLEqPzRKJijB6ZUybZjnwetdZp8Lm", Round: 4}}},
		chainID: "NetXo5iVw1vBoxM",
	},
	{title: "the order of baking operations block, preendorsement, endorsement does not matter",
		signRequestBodies: []string{
			"\"13b3d79f9981ff3a903959741b102d579148d3b1ea56ad7bc77e102def5cc73c49c062217a1500040000002200000004fd5a576ce08fa0e87e7b41d373d04a2df8798b234c7a4f8483a1d839e0066c06\"",
			"\"12b3d79f9981ff3a903959741b102d579148d3b1ea56ad7bc77e102def5cc73c49c062217a1400040000002200000004fd5a576ce08fa0e87e7b41d373d04a2df8798b234c7a4f8483a1d839e0066c06\"",
			"\"11b3d79f99000000220181ff3a903959741b102d579148d3b1ea56ad7bc77e102def5cc73c49c062217a000000006427822b0480a2ea07609835343e53282a2e0d8ef20f54d6a7c1603d3874c2a2a7fceb3d3d00000021000000010200000004000000220000000000000004fffffffd000000040000000415b3aa8c735353cf4cde8aec00319d8922538fef77d44ee6780c8872bf63408bfd5a576ce08fa0e87e7b41d373d04a2df8798b234c7a4f8483a1d839e0066c0600000004a40d1a28000000000002\"",
		},
		expectedStatusCodes: []int{200, 200, 200},
		expectedResponses: []any{SuccessResponse{Signature: "sigVyiC8WmGbyQXU1qvmZZpwmLJpVk9Nr7NZ6hiN1XPNU9XqupEJLRihvggfUFHrPzMwTBTT3xDqESKZJbe1uDuFpBzUm1hZ"},
			SuccessResponse{Signature: "siga1AQYVi1ghZem8jkNUAb4yMAcdqV7P8dQxn4h8kM6EDqs4N7645pGXc6336qs6Tgf2bznBu2Trqz8mzn9WLJ9zTZsiyLw"},
			SuccessResponse{Signature: "sigVTpZfEQumN2togGoB39sDavEzytJnBXAuwmYzzymc882zVoudc6yjGnkgb22MdtCeZ2NREpoW2xg4HjdnXoQ5FsLo6MYR"}},
		watermarkBefore: operationMap{"block": {pkh: {Level: 33, Hash: "vh2DhMVAsCB8C6HxZ4PWqgtJYgb9ddojcjy99dHv131ADW9N91jf", Round: 2}},
			"preendorsement": {pkh: {Level: 33, Hash: "vh1zCCBsR6djpWb4ad5RsAyGnvXUUGza9QfoeMM1VaUsMwfdKXUq", Round: 2}},
			"endorsement":    {pkh: {Level: 33, Hash: "vh3RUn3hLiQFRakQdr8X2wegKyTmGZYqQmf9Nmg5ez4ngUqHwKUR", Round: 2}}},
		watermarkAfter: operationMap{"block": {pkh: {Level: 34, Hash: "vh2E3QPN8R55XtdeZXsPtbgXErMeLcE5YbjDMcUzXsFByL97u5Qc", Round: 4}},
			"preendorsement": {pkh: {Level: 34, Hash: "vh2KHE9afrJBSzLQcnP21cCtHfc9yPsjCVzsbBfLTpzRTenXtp1s", Round: 4}},
			"endorsement":    {pkh: {Level: 34, Hash: "vh216VxjGyVK2XWEQ5gyFcAMLEqPzRKJijB6ZUybZjnwetdZp8Lm", Round: 4}}},
		chainID: "NetXo5iVw1vBoxM",
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
		log.Fatal(container + " container failed to start")
	}
}

func stop_signatory() {
	_, err := exec.Command("docker", "compose", "-f", "./docker-compose.yml", "down").CombinedOutput()
	if err != nil {
		log.Fatal(container + " container failed to stop")
	}
}

func mkdir() {
	_, err := exec.Command("docker", "exec", container, "mkdir", "-p", dir).CombinedOutput()
	if err != nil {
		log.Fatal("failed to make watermark directory")
	}
}

func remove_watermark_files() {
	_, err := exec.Command("docker", "exec", container, "rm", "-f", dir+"*").CombinedOutput()
	if err != nil {
		log.Fatal("failed to remove watermark files")
	}
}

func write_watermark_file(om operationMap, filename string) {
	json, err := json.Marshal(om)
	if err != nil {
		log.Fatal("json marshal failed")
	}
	shell := "echo '" + string(json) + "' >" + dir + filename
	_, err = exec.Command("docker", "exec", container, "bash", "-c", shell).CombinedOutput()
	if err != nil {
		log.Fatal("failed to write watermark file")
	}
}

func read_watermark_file(chainId string) (out []byte) {
	out, err := exec.Command("docker", "exec", container, "cat", dir+chainId+".json").CombinedOutput()
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
	//fmt.Println(string(bytes))
	return resp.StatusCode, bytes
}
