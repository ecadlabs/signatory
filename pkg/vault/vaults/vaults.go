package vaults

import (
	_ "github.com/ecadlabs/signatory/pkg/vault/aws"
	_ "github.com/ecadlabs/signatory/pkg/vault/azure"
	_ "github.com/ecadlabs/signatory/pkg/vault/cloudkms"
	_ "github.com/ecadlabs/signatory/pkg/vault/file"
	_ "github.com/ecadlabs/signatory/pkg/vault/hashicorp"
	_ "github.com/ecadlabs/signatory/pkg/vault/ledger"
	_ "github.com/ecadlabs/signatory/pkg/vault/mem"
	_ "github.com/ecadlabs/signatory/pkg/vault/secureenclave"
	_ "github.com/ecadlabs/signatory/pkg/vault/yubi"
)
