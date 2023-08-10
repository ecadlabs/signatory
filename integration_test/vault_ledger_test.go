package integrationtest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLedgerVault(t *testing.T) {

	tz1alias := "speculos"

	go SpeculosApprove()

	out, err := OctezClient("transfer", "1", "from", tz1alias, "to", "alice", "--burn-cap", "0.06425")

	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")
}

func TestLedgerVaultGetPublicKey(t *testing.T) {
	require.Equal(t, "edpktsKqhvR7kXbRWD7yDgLSD7PZUXvjLqf9SFscXhL52pUStF5nQp", GetPublicKey("tz1RVYaHiobUKXMfJ47F7Rjxx5tu3LC35WSA"))
}
