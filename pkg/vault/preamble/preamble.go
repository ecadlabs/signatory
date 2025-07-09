package preamble

import (
	// Install all backends
	_ "github.com/ecadlabs/signatory/pkg/vault/aws"
	_ "github.com/ecadlabs/signatory/pkg/vault/azure"
	_ "github.com/ecadlabs/signatory/pkg/vault/cloudkms"
	_ "github.com/ecadlabs/signatory/pkg/vault/file"
	_ "github.com/ecadlabs/signatory/pkg/vault/hashicorp"
	_ "github.com/ecadlabs/signatory/pkg/vault/ledger"
	_ "github.com/ecadlabs/signatory/pkg/vault/mem"
	_ "github.com/ecadlabs/signatory/pkg/vault/nitro"
	_ "github.com/ecadlabs/signatory/pkg/vault/pkcs11"
	_ "github.com/ecadlabs/signatory/pkg/vault/yubi"
)
