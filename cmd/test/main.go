package main

import (
	"context"
	"github.com/ecadlabs/signatory/pkg/vault/file"
)

func main() {
	file.NewVault(context.Background(), &file.Config{
		File: "./secret_keys",
	})
}
