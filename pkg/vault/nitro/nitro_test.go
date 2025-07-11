//go:build nitro_test

package nitro

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestNitro(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tmpfd, err := os.CreateTemp("", "nitro_test")
	require.NoError(t, err)
	require.NoError(t, tmpfd.Close())

	storage, err := newFileStorage(tmpfd.Name())
	require.NoError(t, err)

	// generate and import
	v, err := newWithStorage(context.Background(), nil, storage)
	require.NoError(t, err)

	kTypes := []*cryptoutils.KeyType{cryptoutils.KeyEd25519, cryptoutils.KeySecp256k1, cryptoutils.KeyP256, cryptoutils.KeyBLS12_381}
	for _, kt := range kTypes {
		_, err = v.Generate(context.Background(), kt, 1)
		require.NoError(t, err)
	}
	require.Equal(t, 4, len(storage.keys))
	require.NoError(t, v.Close(context.Background()))

	// import back
	v, err = newWithStorage(context.Background(), nil, storage)
	require.NoError(t, err)

	t.Cleanup(func() { v.Close(context.Background()) })

	iter := v.List(context.Background())
keys:
	for {
		key, err := iter.Next()
		if err != nil {
			switch {
			case errors.Is(err, vault.ErrDone):
				break keys
			case errors.Is(err, vault.ErrKey):
				continue keys
			default:
				t.FailNow()
			}
		}

		text := []byte("text_to_sign")
		sig, err := key.Sign(context.Background(), text)
		require.NoError(t, err)

		pub := key.PublicKey()
		require.True(t, pub.VerifySignature(sig, text))
	}
}
