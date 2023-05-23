package integrationtest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCliList(t *testing.T) {
	var c Config
	c.Read()

	out, err := SignatoryCli("list")
	assert.Nil(t, err)
	require.Contains(t, string(out), "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb")
}
