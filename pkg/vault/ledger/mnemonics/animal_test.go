package mnemonics

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMnemonics(t *testing.T) {

	var name Names = Names{C: "calculating", T: "meerkat", H: "straight", D: "beetle"}
	n, err := GetName("12345")
	// n, err := GetAnimalName("12345")
	require.NoError(t, err)
	fmt.Println("Name", n)
	require.Equal(t, name, *n)
}
