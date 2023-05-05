package integrationtest

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
)

const (
	config        = "signatory.yaml"
	account       = "tz1RKGhRF4TZNCXEfwyqZshGsVfrZeVU446B"
	alias         = "opstest"
	account1      = "tz1R8HJMzVdZ9RqLCknxeq9w5rSbiqJ41szi"
	alias1        = "opstest1"
	contract      = "contract.event.tz"
	contractAlias = "emit_event"
)

type testCase struct {
	opName         string
	testSetupOps   [][]string
	testOp         []string
	account        string
	allowPolicy    map[string][]string
	notAllowPolicy map[string][]string
}

// these test cases are not atomic -- some tests depend on previous tests (order matters)
var testcases = []testCase{
	{
		opName:         "reveal",
		testSetupOps:   [][]string{{"-w", "1", "transfer", "100", "from", "alice", "to", alias, "--burn-cap", "0.06425"}},
		testOp:         []string{"reveal", "key", "for", alias},
		account:        account,
		allowPolicy:    map[string][]string{"generic": {"reveal"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"reveal"})},
	},
	{
		opName:         "register_global_constant",
		testSetupOps:   nil,
		testOp:         []string{"register", "global", "constant", "999", "from", alias, "--burn-cap", "0.017"},
		account:        account,
		allowPolicy:    map[string][]string{"generic": {"register_global_constant"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"register_global_constant"})},
	},
	{
		opName:         "transaction",
		testSetupOps:   nil,
		account:        account,
		testOp:         []string{"transfer", "1", "from", alias, "to", "alice", "--burn-cap", "0.06425"},
		allowPolicy:    map[string][]string{"generic": {"transaction"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"transaction"})},
	},
	{
		opName:         "delegation",
		testSetupOps:   nil,
		account:        account,
		testOp:         []string{"register", "key", alias, "as", "delegate"},
		allowPolicy:    map[string][]string{"generic": {"delegation"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"delegation"})},
	},
	{
		opName:         "set_deposits_limit",
		testSetupOps:   nil,
		account:        account,
		testOp:         []string{"set", "deposits", "limit", "for", alias, "to", "10000"},
		allowPolicy:    map[string][]string{"generic": {"set_deposits_limit"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"set_deposits_limit"})},
	},
	{
		opName:         "update_consensus_key",
		testSetupOps:   nil,
		account:        account,
		testOp:         []string{"set", "consensus", "key", "for", alias, "to", alias1},
		allowPolicy:    map[string][]string{"generic": {"update_consensus_key"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"update_consensus_key"})},
	},
	{
		opName:         "origination",
		testSetupOps:   nil,
		account:        account,
		testOp:         []string{"originate", "contract", contractAlias, "transferring", "1", "from", alias, "running", contract, "--burn-cap", "0.4"},
		allowPolicy:    map[string][]string{"generic": {"origination", "transaction"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"origination"})},
	},
	{
		opName:         "increase_paid_storage",
		testSetupOps:   nil,
		account:        account,
		testOp:         []string{"increase", "the", "paid", "storage", "of", contractAlias, "by", "0x5c", "bytes", "from", alias},
		allowPolicy:    map[string][]string{"generic": {"increase_paid_storage"}},
		notAllowPolicy: map[string][]string{"generic": getAllOpsExcluding([]string{"increase_paid_storage"})},
	},
}

func TestOperationAllowPolicy(t *testing.T) {
	defer delete_contracts_aliases()
	for _, test := range testcases {
		t.Run(test.opName, func(t *testing.T) {
			//first, do any setup steps that have to happen before the operation to be tested
			for _, setupOp := range test.testSetupOps {
				out, err := OctezClient(setupOp...)
				require.NoError(t, err)
				require.Contains(t, string(out), "Operation successfully injected in the node")
			}

			//next, configure every operation allowed except for the one tested, to test it will be denied
			var c Config
			c.Read(config)
			c.Tezos[test.account].Allow = test.notAllowPolicy
			backup_then_update_config(c)
			defer restore_config()
			restart_signatory()
			out, err := OctezClient(test.testOp...)
			assert.Error(t, err)
			require.Contains(t, string(out), "operation `"+test.opName+"' is not allowed")

			//finally, configure the operation being tested is the only one allowed and test it is successful
			c.Read(config)
			c.Tezos[test.account].Allow = test.allowPolicy
			c.Write(config)
			restart_signatory()
			out, err = OctezClient(test.testOp...)
			if err != nil {
				log.Println("error received: " + err.Error() + " " + string(out))
			}
			assert.NoError(t, err)
			require.Contains(t, string(out), "Operation successfully injected in the node")
		})
	}
}

func getAllOps() []string {
	return []string{"activate_account", "ballot", "dal_attestation", "dal_publish_slot_header", "delegation",
		"double_baking_evidence", "double_endorsement_evidence", "double_preendorsement_evidence", "drain_delegate",
		"endorsement", "event", "failing_noop", "increase_paid_storage", "origination", "preendorsement", "proposals",
		"register_global_constant", "reveal", "sc_rollup_add_messages", "sc_rollup_cement",
		"sc_rollup_execute_outbox_message", "sc_rollup_originate", "sc_rollup_publish", "sc_rollup_recover_bond",
		"sc_rollup_refute", "sc_rollup_timeout", "seed_nonce_revelation", "set_deposits_limit", "transaction",
		"transfer_ticket", "update_consensus_key", "vdf_revelation", "zk_rollup_origination", "zk_rollup_publish", "zk_rollup_update"}
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
