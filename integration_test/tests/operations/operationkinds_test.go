package operations

import (
	"log"
	"testing"

	integrationtest "github.com/ecadlabs/signatory/integration_test/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
)

const (
	account       = integrationtest.OpstestPKH
	alias         = integrationtest.OpstestAlias
	account1      = integrationtest.Opstest1PKH
	alias1        = integrationtest.Opstest1Alias
	aliasbaker1   = integrationtest.Baker1Alias
	accountbaker1 = integrationtest.Baker1PKH
	contract      = "contract.event.tz"
	contractAlias = "emit_event"
	vault         = "File"
)

type testCase struct {
	op                  string
	kind                string
	testSetupOps        [][]string
	testOp              []string
	account             string
	allowPolicy         map[string][]string
	notAllowPolicy      map[string][]string
	successMessage      string
	validateOctezReturn bool
}

// these test cases are not atomic -- some tests depend on previous tests (order matters)
var testcases = []testCase{
	{
		kind:           "stake",
		op:             "generic",
		testSetupOps:   nil,
		testOp:         []string{"-d", "/home/tezos/manual-bake-client", "-w", "none", "stake", "10000", "for", aliasbaker1},
		account:        accountbaker1,
		allowPolicy:    map[string][]string{"generic": {"stake"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"stake"})},
		successMessage: "injected",
	},
	{
		kind:           "attestation",
		op:             "attestation",
		testSetupOps:   nil,
		testOp:         []string{"-d", "/home/tezos/manual-bake-client", "-w", "none", "attest", "for", aliasbaker1, "--force"},
		account:        accountbaker1,
		allowPolicy:    map[string][]string{"attestation": {}},
		notAllowPolicy: map[string][]string{"generic": getAllOps(), "preattestation": {}, "block": {}},
		successMessage: "injected",
	},
	{
		kind:           "preattestation",
		op:             "preattestation",
		testSetupOps:   nil,
		testOp:         []string{"-d", "/home/tezos/manual-bake-client", "-w", "none", "preattest", "for", aliasbaker1, "--force"},
		account:        accountbaker1,
		allowPolicy:    map[string][]string{"preattestation": {}},
		notAllowPolicy: map[string][]string{"generic": getAllOps(), "attestation": {}, "block": {}},
		successMessage: "injected",
	},
	{
		kind:           "block",
		op:             "block",
		testSetupOps:   nil,
		testOp:         []string{"-d", "/home/tezos/manual-bake-client", "-w", "none", "bake", "for", aliasbaker1, "--force", "--minimal-timestamp"},
		account:        accountbaker1,
		allowPolicy:    map[string][]string{"block": {}},
		notAllowPolicy: map[string][]string{"generic": getAllOps(), "attestation": {}, "preattestation": {}},
		successMessage: "injected",
	},
	{
		kind:           "reveal",
		op:             "generic",
		testSetupOps:   [][]string{{"-w", "1", "transfer", "100", "from", "alice", "to", alias, "--burn-cap", "0.06425"}},
		testOp:         []string{"reveal", "key", "for", alias},
		account:        account,
		allowPolicy:    map[string][]string{"generic": {"reveal"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"reveal"})},
		successMessage: "Operation successfully injected in the node",
	},
	{
		kind:           "register_global_constant",
		op:             "generic",
		testSetupOps:   nil,
		testOp:         []string{"register", "global", "constant", "999", "from", alias, "--burn-cap", "0.017"},
		account:        account,
		allowPolicy:    map[string][]string{"generic": {"register_global_constant"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"register_global_constant"})},
		successMessage: "Operation successfully injected in the node",
	},
	{
		kind:           "transaction",
		op:             "generic",
		testSetupOps:   nil,
		account:        account,
		testOp:         []string{"transfer", "1", "from", alias, "to", "alice", "--burn-cap", "0.06425"},
		allowPolicy:    map[string][]string{"generic": {"transaction"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"transaction"})},
		successMessage: "Operation successfully injected in the node",
	},
	{
		kind:           "delegation",
		op:             "generic",
		testSetupOps:   nil,
		account:        account,
		testOp:         []string{"register", "key", alias, "as", "delegate"},
		allowPolicy:    map[string][]string{"generic": {"delegation"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"delegation"})},
		successMessage: "Operation successfully injected in the node",
	},
	// {
	// 	kind:           "set_deposits_limit",
	// 	op:             "generic",
	// 	testSetupOps:   nil,
	// 	account:        account,
	// 	testOp:         []string{"set", "deposits", "limit", "for", alias, "to", "10000"},
	// 	allowPolicy:    map[string][]string{"generic": {"set_deposits_limit"}},
	// 	notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"set_deposits_limit"})},
	// 	successMessage: "Operation successfully injected in the node",
	// },
	{
		kind:           "update_consensus_key",
		op:             "generic",
		testSetupOps:   nil,
		account:        account,
		testOp:         []string{"set", "consensus", "key", "for", alias, "to", alias1},
		allowPolicy:    map[string][]string{"generic": {"update_consensus_key"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"update_consensus_key"})},
		successMessage: "Operation successfully injected in the node",
	},
	{
		kind:                "origination",
		op:                  "generic",
		testSetupOps:        nil,
		account:             account,
		testOp:              []string{"originate", "contract", contractAlias, "transferring", "1", "from", alias, "running", contract, "--burn-cap", "0.4"},
		allowPolicy:         map[string][]string{"generic": {"origination", "transaction", "reveal"}},
		notAllowPolicy:      map[string][]string{"generic": getAllOpsExcluding([]string{"origination"})},
		successMessage:      "Operation successfully injected in the node",
		validateOctezReturn: true,
	},
	{
		kind:           "pack",
		op:             "pack",
		testSetupOps:   nil,
		testOp:         []string{"sign", "bytes", "0x050000000a68656c6c6f", "for", alias}, // 0x05 magic byte + packed nat 42
		account:        account,
		allowPolicy:    map[string][]string{"pack": {}},
		notAllowPolicy: map[string][]string{"generic": getAllOps(), "attestation": {}, "preattestation": {}, "block": {}},
		successMessage: "Signature:",
	},
	// {
	// 	kind:           "increase_paid_storage",
	// 	op:             "generic",
	// 	testSetupOps:   nil,
	// 	account:        account,
	// 	testOp:         []string{"increase", "the", "paid", "storage", "of", contractAlias, "by", "0x5c", "bytes", "from", alias},
	// 	allowPolicy:    map[string][]string{"generic": {"increase_paid_storage"}},
	// 	notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"increase_paid_storage"})},
	// 	successMessage: "Operation successfully injected in the node",
	// },
}

func TestOperationAllowPolicy(t *testing.T) {
	defer integrationtest.Clean_tezos_folder()

	// Get chain_id once for the manual-bake chain
	expectedChainID, err := integrationtest.GetChainID("-d", "/home/tezos/manual-bake-client")
	require.NoError(t, err, "should be able to get chain_id from manual-bake node")

	for _, test := range testcases {
		t.Run(test.kind, func(t *testing.T) {
			//first, do any setup steps that have to happen before the operation to be tested
			for _, setupOp := range test.testSetupOps {
				out, err := integrationtest.OctezClient(setupOp...)
				assert.NoError(t, err)
				require.Contains(t, string(out), "Operation successfully injected in the node")
			}

			metrics0 := integrationtest.GetMetrics(test.account, test.kind, test.op, vault, "")

			//next, configure every operation allowed except for the one tested, to test it will be denied
			var c integrationtest.Config
			c.Read()
			c.Tezos[test.account].Allow = test.notAllowPolicy
			integrationtest.Update_config(c)
			defer integrationtest.Restore_config()
			integrationtest.Restart_signatory()
			out, err := integrationtest.OctezClient(test.testOp...)
			if test.op == "generic" {
				//the baking operations in octez-client do not return an error when they fail
				//so, we do this assert when we can
				assert.Error(t, err)
			}
			assert.Contains(t, string(out), "`"+test.kind+"' is not allowed")

			metrics1 := integrationtest.GetMetrics(test.account, test.kind, test.op, vault, "")
			//this should be changed to AssertMetricsFailure
			integrationtest.AssertMetricsSuccessUnchanged(t, metrics0, metrics1)

			//finally, configure the operation being tested as the only one allowed and test it is successful
			c.Read()
			c.Tezos[test.account].Allow = test.allowPolicy
			c.Write()
			integrationtest.Restart_signatory()
			out, err = integrationtest.OctezClient(test.testOp...)
			if err != nil {
				log.Println("error received: " + err.Error() + " " + string(out))
			}
			assert.NoError(t, err)
			require.Contains(t, string(out), test.successMessage)
			metrics2 := integrationtest.GetMetrics(test.account, test.kind, test.op, vault, "")
			integrationtest.AssertMetricsSuccessIncremented(t, metrics1, metrics2)

			// Baking operations should have chain_id matching the manual-bake chain
			if test.op == "attestation" || test.op == "preattestation" || test.op == "block" {
				chainID := integrationtest.ExtractChainIDFromMetrics(test.account, test.op, vault)
				assert.Equal(t, expectedChainID, chainID, "chain_id in metrics should match manual-bake chain")
			}
		})
	}
}

func getAllOps() []string {
	return []string{ // operations available in both proto_022_PsRiotum and proto_023_PtSeouLo
		"activate_account", "attestations_aggregate",
		"ballot", "dal_entrapment_evidence", "dal_publish_commitment", "delegation",
		"double_baking_evidence", "drain_delegate", "failing_noop", "increase_paid_storage",
		"origination", "proposals", "register_global_constant", "reveal",
		"seed_nonce_revelation", "set_deposits_limit", "signature_prefix",
		"smart_rollup_add_messages", "smart_rollup_cement",
		"smart_rollup_execute_outbox_message", "smart_rollup_originate",
		"smart_rollup_publish", "smart_rollup_recover_bond", "smart_rollup_refute",
		"smart_rollup_timeout", "transaction", "transfer_ticket", "update_consensus_key",
		"vdf_revelation", "zk_rollup_origination", "zk_rollup_publish", "zk_rollup_update",
		"finalize_unstake", "set_delegate_parameters", "stake", "unstake",
	}
}

func getAllOpsExcluding(exclude []string) []string {
	var ops []string
	for _, op := range getAllOps() {
		if !slices.Contains(exclude, op) {
			ops = append(ops, op)
		}
	}
	return ops
}
