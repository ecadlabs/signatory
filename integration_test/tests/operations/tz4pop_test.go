package operations

import (
	"strings"
	"testing"

	integrationtest "github.com/ecadlabs/signatory/integration_test/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProofOfPossessionAllowPolicy(t *testing.T) {
	defer integrationtest.Clean_tezos_folder()
	// policies
	var c integrationtest.Config
	c.Read()
	pkh := integrationtest.PKH.Tz4Pop()

	defer integrationtest.Restore_config()

	protocol, err := integrationtest.GetCurrentProtocol()
	assert.NoError(t, err)

	if strings.Compare(protocol, "PtSeouL") >= 0 { // only test this for protocols >= PtSeouL
		// Test with allow_proof_of_possession = false (not allowed)
		c.Tezos[pkh] = &integrationtest.TezosPolicy{
			Allow: map[string][]string{
				"generic": {"reveal"},
			},
			AllowProofOfPossession: false,
		}
		integrationtest.Update_config(c)
		integrationtest.Restart_signatory()

		out, err := integrationtest.OctezClient("reveal", "key", "for", "tz4pop")
		assert.Error(t, err)
		require.Contains(t, string(out), "proof of possession is not allowed")
	}

	{
		// Test with allow_proof_of_possession = true (allowed)
		c.Tezos[pkh] = &integrationtest.TezosPolicy{
			Allow: map[string][]string{
				"generic": {"reveal"},
			},
			AllowProofOfPossession: true,
		}
		integrationtest.Update_config(c)
		integrationtest.Restart_signatory()

		out, err := integrationtest.OctezClient("reveal", "key", "for", "tz4pop")
		assert.NoError(t, err)
		require.Contains(t, string(out), "Operation successfully injected in the node")
	}
}
