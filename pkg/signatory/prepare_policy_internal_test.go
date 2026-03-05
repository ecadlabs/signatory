//go:build !integration

package signatory

import (
	stderr "errors"
	"testing"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/stretchr/testify/require"
)

func TestPreparePolicyDeprecatedConfigMarshalFailureIsNonFatal(t *testing.T) {
	oldMarshal := yamlMarshal
	yamlMarshal = func(interface{}) ([]byte, error) {
		return nil, stderr.New("yaml marshal failed")
	}
	t.Cleanup(func() {
		yamlMarshal = oldMarshal
	})

	keyHash := &tz.Ed25519PublicKeyHash{1, 2, 3}
	cfg := hashmap.NewPublicKeyHashMap([]hashmap.PublicKeyKV[*config.TezosPolicy]{
		{
			Key: keyHash,
			Val: &config.TezosPolicy{
				AllowedOperations: []string{"generic"},
				AllowedKinds:      []string{"transaction"},
			},
		},
	})

	policy, err := PreparePolicy(cfg)
	require.NoError(t, err)

	prepared, ok := policy.Get(keyHash)
	require.True(t, ok)
	require.NotNil(t, prepared)
	require.Equal(t, []string{"generic"}, prepared.AllowedRequests)
	require.Equal(t, []string{"transaction"}, prepared.AllowedOps)
}
