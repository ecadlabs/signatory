//go:build nitro_test

package nitro

import (
	"context"
	"errors"
	"flag"
	"net"
	"testing"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/stretchr/testify/require"
)

type dummyCred struct{}

type inMemoryStorage struct {
	*fileStorage
}

func newInMemoryStorage() *inMemoryStorage {
	return &inMemoryStorage{
		fileStorage: &fileStorage{
			keys: make([]*encryptedKey, 0),
		},
	}
}

func (f *inMemoryStorage) ImportKey(ctx context.Context, encryptedKey *encryptedKey) (err error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	f.keys = append(f.keys, encryptedKey)
	return nil
}

func TestNitro(t *testing.T) {
	address := flag.String("connect", "localhost:6543", "Address of an enclave mockup")
	flag.Parse()

	storage := newInMemoryStorage()

	// generate and import
	conn, err := net.Dial("tcp", *address)
	require.NoError(t, err)
	var cred dummyCred
	v, err := newWithConn(context.Background(), conn, &cred, storage)
	require.NoError(t, err)

	kTypes := []*cryptoutils.KeyType{cryptoutils.KeyEd25519, cryptoutils.KeySecp256k1, cryptoutils.KeyP256, cryptoutils.KeyBLS12_381}
	for _, kt := range kTypes {
		_, err = v.Generate(context.Background(), kt, 1)
		require.NoError(t, err)
	}
	require.Equal(t, 4, len(storage.keys))
	require.NoError(t, v.Close(context.Background()))

	// import back
	conn, err = net.Dial("tcp", *address)
	require.NoError(t, err)
	v, err = newWithConn(context.Background(), conn, &cred, storage)
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
