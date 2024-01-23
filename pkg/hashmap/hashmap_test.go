package hashmap_test

import (
	"encoding/json"
	"testing"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestHashMap(t *testing.T) {
	m := hashmap.New[tz.EncodedPublicKeyHash]([]hashmap.KV[crypt.PublicKeyHash, string]{
		{
			&tz.Ed25519PublicKeyHash{0}, "a",
		},
		{
			&tz.Ed25519PublicKeyHash{1}, "b",
		},
		{
			&tz.Ed25519PublicKeyHash{2}, "c",
		},
		{
			&tz.Ed25519PublicKeyHash{3}, "d",
		},
	})

	t.Run("JSON", func(t *testing.T) {
		buf, err := json.Marshal(m)
		require.NoError(t, err)

		var res hashmap.HashMap[tz.EncodedPublicKeyHash, crypt.PublicKeyHash, string]
		err = json.Unmarshal(buf, &res)
		require.NoError(t, err)
		require.Equal(t, m, res)
	})

	t.Run("YAML", func(t *testing.T) {
		buf, err := yaml.Marshal(m)
		require.NoError(t, err)
		var res hashmap.HashMap[tz.EncodedPublicKeyHash, crypt.PublicKeyHash, string]
		err = yaml.Unmarshal(buf, &res)
		require.NoError(t, err)
		require.Equal(t, m, res)
	})
}
