package signatory

import (
	"context"
	"crypto"
	"testing"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/segmentio/ksuid"
	"github.com/stretchr/testify/require"
)

type vaultMock struct {
	keys map[string]cryptoutils.PrivateKey
}

type keyMock struct {
	id  string
	key crypto.PublicKey
}

func (k *keyMock) PublicKey() crypto.PublicKey { return k.key }
func (k *keyMock) ID() string                  { return k.id }

func (v *vaultMock) GetPublicKey(ctx context.Context, id string) (StoredKey, error) {
	pk, ok := v.keys[id]
	if !ok {
		return nil, ErrVaultNotFound
	}
	return &keyMock{id: id, key: pk.Public()}, nil
}

func (v *vaultMock) ListPublicKeys(ctx context.Context) ([]StoredKey, error) {
	ret := make([]StoredKey, 0)
	for id, key := range v.keys {
		ret = append(ret, &keyMock{id: id, key: key.Public()})
	}
	return ret, nil
}

func (v *vaultMock) Sign(ctx context.Context, digest []byte, key StoredKey) (cryptoutils.Signature, error) {
	return nil, ErrVaultNotFound
}

func (v *vaultMock) Name() string { return "mock" }

func (v *vaultMock) Import(ctx context.Context, pk cryptoutils.PrivateKey) (StoredKey, error) {
	id := ksuid.New().String()
	v.keys[id] = pk
	return &keyMock{id: id, key: pk.Public()}, nil
}

func TestSignatory(t *testing.T) {
	vault := &vaultMock{keys: make(map[string]cryptoutils.PrivateKey)}
	s := Signatory{
		Vaults:    []Vault{vault},
		Config:    make(config.TezosConfig),
		Watermark: NewIgnore(),
	}

	pk := "edsk4FTF78Qf1m2rykGpHqostAiq5gYW4YZEoGUSWBTJr2njsDHSnd"

	imported, err := s.Import(context.Background(), vault, pk, nil)
	require.NoError(t, err)
	require.Equal(t, "edpkv45regue1bWtuHnCgLU8xWKLwa9qRqv4gimgJKro4LSc3C5VjV", imported.PublicKey)
	require.Equal(t, "tz1LggX2HUdvJ1tF4Fvv8fjsrzLeW4Jr9t2Q", imported.PublicKeyHash)

	list, err := s.ListPublicKeys(context.Background())
	require.NoError(t, err)
	require.Equal(t, []*PublicKey{imported}, list)
}
