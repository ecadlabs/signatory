package vsock_test

import (
	"testing"

	"github.com/ecadlabs/signatory/pkg/vault/nitro/vsock"
	"github.com/stretchr/testify/require"
)

func TestVSock(t *testing.T) {
	listener, err := vsock.Listen(&vsock.Addr{CID: vsock.ContextAny, Port: vsock.PortAny})
	require.NoError(t, err)

	go func() {
		conn, err := listener.Accept()
		require.NoError(t, err)

		var buf [8]byte
		n, err := conn.Read(buf[:])
		require.NoError(t, err)
		require.Equal(t, len(buf), n)

		n, err = conn.Write(buf[:])
		require.NoError(t, err)
		require.Equal(t, len(buf), n)
	}()

	data := []byte("datadata")

	conn, err := vsock.Dial(&vsock.Addr{CID: vsock.ContextLocal, Port: listener.Addr().(*vsock.Addr).Port})
	require.NoError(t, err)

	n, err := conn.Write(data)
	require.NoError(t, err)
	require.Equal(t, len(data), n)

	var buf [8]byte
	n, err = conn.Read(buf[:])
	require.NoError(t, err)
	require.Equal(t, len(buf), n)
	require.Equal(t, data[:], buf[:])
}
