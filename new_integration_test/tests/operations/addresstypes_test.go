package integrationtest

import (
	"testing"

	integrationtest "github.com/ecadlabs/signatory/new_integration_test/tests"
	"github.com/stretchr/testify/require"
)

func TestTz1(t *testing.T) {
	out, err := integrationtest.OctezClient("-w", "1", "transfer", "1", "from", "tz1alias", "to", "alice", "--burn-cap", "0.06425")
	require.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	out, err = integrationtest.OctezClient("-w", "1", "transfer", "100", "from", "alice", "to", "tz1alias", "--burn-cap", "0.06425")
	require.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")
}

func TestTz2(t *testing.T) {
	out, err := integrationtest.OctezClient("-w", "1", "transfer", "1", "from", "tz2alias", "to", "alice", "--burn-cap", "0.06425")
	require.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	out, err = integrationtest.OctezClient("-w", "1", "transfer", "100", "from", "alice", "to", "tz2alias", "--burn-cap", "0.06425")
	require.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")
}

func TestTz3(t *testing.T) {
	out, err := integrationtest.OctezClient("-w", "1", "transfer", "1", "from", "tz3alias", "to", "alice", "--burn-cap", "0.06425")
	require.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	out, err = integrationtest.OctezClient("-w", "1", "transfer", "100", "from", "alice", "to", "tz3alias", "--burn-cap", "0.06425")
	require.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")
}

func TestTz4(t *testing.T) {
	out, err := integrationtest.OctezClient("-w", "1", "transfer", "1", "from", "tz4alias", "to", "alice", "--burn-cap", "0.06425")
	require.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	out, err = integrationtest.OctezClient("-w", "1", "transfer", "1", "from", "alice", "to", "tz4alias", "--burn-cap", "0.06425")
	require.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")
}
