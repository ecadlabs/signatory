package secureenclave

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	stderr "errors"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/vault/secureenclave/cryptokit"
	"github.com/spf13/cobra"
)

func writeRename(dir, name string, buf []byte) error {
	fd, err := os.CreateTemp(dir, name+"_*")
	if err != nil {
		return err
	}
	defer fd.Close()
	if _, err := fd.Write(buf); err != nil {
		return err
	}
	if err := fd.Sync(); err != nil {
		return err
	}
	newpath := filepath.Join(dir, name)
	return os.Rename(fd.Name(), newpath)
}

func newGenerateCommand(g config.GlobalContext) *cobra.Command {
	var id string
	cmd := cobra.Command{
		Use:   "gen-key",
		Short: "Generate new encrypted key",
		RunE: func(cmd *cobra.Command, args []string) error {
			var storage []*storageEntry
			name := filepath.Join(g.BaseDir(), defaultKeysFile)
			buf, err := os.ReadFile(name)
			if err != nil {
				if !stderr.Is(err, os.ErrNotExist) {
					return fmt.Errorf("(SecureEnclave): %w", err)
				}
			} else if err := json.Unmarshal(buf, &storage); err != nil {
				return fmt.Errorf("(SecureEnclave): %w", err)
			}

			idx := make(map[string]*storageEntry)
			for _, e := range storage {
				if e.ID != "" {
					if _, ok := idx[e.ID]; ok {
						return fmt.Errorf("(SecureEnclave): key id `%s' is already in use", e.ID)
					}
					idx[e.ID] = e
				}
			}
			if id != "" {
				if _, ok := idx[id]; ok {
					return fmt.Errorf("(SecureEnclave): key id `%s' is already in use", id)
				}
			}

			priv, err := cryptokit.NewPrivateKey()
			if err != nil {
				return fmt.Errorf("(SecureEnclave): %w", err)
			}

			entry := storageEntry{
				ID:    id,
				Value: priv.Bytes(),
			}
			storage = append(storage, &entry)
			if buf, err = json.MarshalIndent(storage, "", "    "); err != nil {
				return fmt.Errorf("(SecureEnclave): %w", err)
			}
			if err = writeRename(g.BaseDir(), defaultKeysFile, buf); err != nil {
				return fmt.Errorf("(SecureEnclave): %w", err)
			}

			p, err := x509.ParsePKIXPublicKey(priv.Public().DERBytes()) // cryptoutils wrapper is not needed here because SE supports P256 curve only
			if err != nil {
				return fmt.Errorf("(SecureEnclave): %w", err)
			}
			pub, err := crypt.NewPublicKeyFrom(p)
			if err != nil {
				return fmt.Errorf("(SecureEnclave): %w", err)
			}
			fmt.Printf("Public Key Hash: %s\n", pub.Hash().String())
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&id, "id", "i", "", "Key ID")
	return &cmd
}

func newSecureEnclaveCommand(g config.GlobalContext) *cobra.Command {
	cmd := cobra.Command{
		Use:   "secure-enclave",
		Short: "Apple SecureEnclave operations",
	}
	cmd.AddCommand(newGenerateCommand(g))
	return &cmd
}
