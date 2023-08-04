package integrationtest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCliList(t *testing.T) {
	var c Config
	c.Read()

	out, err := SignatoryCli("list")
	assert.Nil(t, err)
	require.Contains(t, string(out), "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb")
}

func TestCliUsage(t *testing.T) {
	out, err := SignatoryCli()
	assert.Nil(t, err)
	require.Contains(t, string(out), "Usage:")
	require.Contains(t, string(out), "signatory-cli [command]")
	require.Contains(t, string(out), "completion    Generate the autocompletion script for the specified shell")
	require.Contains(t, string(out), "help          Help about any command")
	require.Contains(t, string(out), "import        Import Tezos private keys (edsk..., spsk..., p2sk...)")
	require.Contains(t, string(out), "ledger        Ledger specific operations")
	require.Contains(t, string(out), "list          List public keys")
	require.Contains(t, string(out), "list-ops      Print possible operation types inside the `generic` request")
	require.Contains(t, string(out), "list-requests Print possible request types")
	require.Contains(t, string(out), "version       Show signatory image version/release (short alias 'v')")
}

// If/when Issue #425 is fixed, this test will break.  to fix it, leverage the function in this package named "getAllOps"
func TestCliListOps(t *testing.T) {
	out, err := SignatoryCli("list-ops")
	assert.Nil(t, err)
	require.Contains(t, string(out), "Possible operation types:")
	require.Contains(t, string(out), "- activate_account")
	require.Contains(t, string(out), "- ballot")
	require.Contains(t, string(out), "- delegation")
	require.Contains(t, string(out), "- double_baking_evidence")
	require.Contains(t, string(out), "- double_endorsement_evidence")
	require.Contains(t, string(out), "- double_preendorsement_evidence")
	require.Contains(t, string(out), "- drain_delegate")
	require.Contains(t, string(out), "- endorsement")
	require.Contains(t, string(out), "- endorsement_with_slot")
	require.Contains(t, string(out), "- failing_noop")
	require.Contains(t, string(out), "- increase_paid_storage")
	require.Contains(t, string(out), "- origination")
	require.Contains(t, string(out), "- preendorsement")
	require.Contains(t, string(out), "- proposals")
	require.Contains(t, string(out), "- register_global_constant")
	require.Contains(t, string(out), "- reveal")
	require.Contains(t, string(out), "- seed_nonce_revelation")
	require.Contains(t, string(out), "- set_deposits_limit")
	require.Contains(t, string(out), "- transaction")
	require.Contains(t, string(out), "- update_consensus_key")
	require.Contains(t, string(out), "- vdf_revelation")
}

func TestCliListRequests(t *testing.T) {
	out, err := SignatoryCli("list-requests")
	assert.Nil(t, err)
	require.Contains(t, string(out), "Possible request types:")
	require.Contains(t, string(out), "- block")
	require.Contains(t, string(out), "- endorsement")
	require.Contains(t, string(out), "- generic")
	require.Contains(t, string(out), "- preendorsement")
}

func TestCliHelp(t *testing.T) {
	usage, err := SignatoryCli()
	assert.Nil(t, err)
	help, err := SignatoryCli("help")
	assert.Nil(t, err)
	require.Contains(t, string(help), string(usage))
}

func TestCliLedgerUsage(t *testing.T) {
	out, err := SignatoryCli("ledger")
	assert.Nil(t, err)
	require.Contains(t, string(out), "Ledger specific operations")
	require.Contains(t, string(out), "Usage:")
	require.Contains(t, string(out), "signatory-cli ledger [command]")
	require.Contains(t, string(out), "Available Commands:")
	require.Contains(t, string(out), "deauthorize-baking  Deuthorize a key")
	require.Contains(t, string(out), "get-high-watermark  Get high water mark")
	require.Contains(t, string(out), "get-high-watermarks Get all high water marks and chain ID")
	require.Contains(t, string(out), "list                List connected Ledgers")
	require.Contains(t, string(out), "set-high-watermark  Set high water mark")
	require.Contains(t, string(out), "setup-baking        Authorize a key for baking")
	require.Contains(t, string(out), "Use \"signatory-cli ledger [command] --help\" for more information about a command.")
}

func TestCliLedgerList(t *testing.T) {
	out, err := SignatoryCli("ledger", "-t", "tcp://speculos:9999", "list")
	assert.Nil(t, err)
	require.Contains(t, string(out), "Path:  		speculos:9999")
	require.Contains(t, string(out), "ID:")
	require.Contains(t, string(out), "Version:")
}

func TestCliVersion(t *testing.T) {
	v, err := SignatoryCli("v")
	assert.Nil(t, err)
	require.Contains(t, string(v), "Release Version: ")
	require.Greater(t, len(v), len("Release Version: ")+4)
	version, err := SignatoryCli("version")
	require.Equal(t, v, version)
}
