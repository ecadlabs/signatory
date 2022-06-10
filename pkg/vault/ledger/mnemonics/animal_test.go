package mnemonics

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMnemonics(t *testing.T) {

	var name Names = Names{C: "frigid", T: "hamster", H: "frigid", D: "numbat"}
	s, err := hex.DecodeString("49505c50ff4717afa00b0be32a065c835080b42c")
	require.NoError(t, err)
	n, err := Getname(s)
	require.NoError(t, err)
	fmt.Println("Name", n)
	require.Equal(t, name, *n)
}
