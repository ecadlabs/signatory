package mnemonic

import (
	"fmt"
	"math/big"

	"golang.org/x/crypto/blake2b"
)

type Mnemonic struct {
	C, T, H, D string
}

func (m *Mnemonic) String() string {
	return fmt.Sprintf("%s-%s-%s-%s", m.C, m.T, m.H, m.D)
}

func toBigInt(src []byte) *big.Int {
	tmp := make([]byte, len(src))
	for i, v := range src {
		tmp[len(tmp)-1-i] = v
	}
	var x big.Int
	return x.SetBytes(tmp)
}

func pickWord(x *big.Int, words []string) string {
	var i big.Int
	i.Mod(x, big.NewInt(int64(len(words))))
	return words[i.Int64()]
}

func GenerateMnemonic(src []byte) Mnemonic {
	h1 := blake2b.Sum256(src)
	h2 := blake2b.Sum256(h1[:])
	h3 := blake2b.Sum256(h2[:])
	h4 := blake2b.Sum256(h3[:])
	return Mnemonic{
		C: pickWord(toBigInt(h1[:]), adjectives),
		T: pickWord(toBigInt(h2[:]), animals),
		H: pickWord(toBigInt(h3[:]), adjectives),
		D: pickWord(toBigInt(h4[:]), animals),
	}
}
