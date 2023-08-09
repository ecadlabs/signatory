package integrationtest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

//there are enough existing integration tests using tz1 and tz3 addresses that it would be redundant to do so here

func TestTz4(t *testing.T) {
	//flextesa does not start when we try to use a tz4 bootstrap account, so, we have to fund it first
	out, err := OctezClient("-w", "1", "transfer", "200", "from", "alice", "to", "tz4alias", "--burn-cap", "0.06425")
	require.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	out, err = OctezClient("-w", "1", "transfer", "100", "from", "tz4alias", "to", "alice", "--burn-cap", "0.06425")
	require.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")
}

func TestTz2(t *testing.T) {
	out, err := OctezClient("-w", "1", "transfer", "100", "from", "tz2alias", "to", "alice", "--burn-cap", "0.06425")
	require.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")
}
