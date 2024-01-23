package main

import (
	"encoding/hex"
	"fmt"

	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/spf13/cobra"
)

func NewAuthRequestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authenticate <secret key> <request pkh> <request body>",
		Short: "Authenticate (sign) a sign request",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			priv, err := crypt.ParsePrivateKey([]byte(args[0]))
			if err != nil {
				return err
			}

			pkh, err := b58.ParsePublicKeyHash([]byte(args[0]))
			if err != nil {
				return err
			}

			msg, err := hex.DecodeString(args[2])
			if err != nil {
				return err
			}

			req := signatory.SignRequest{
				Message:       msg,
				PublicKeyHash: pkh,
			}

			data, err := signatory.AuthenticatedBytesToSign(&req)
			if err != nil {
				return err
			}

			sig, err := priv.Sign(data)
			if err != nil {
				return err
			}
			fmt.Println(sig)
			return nil
		},
	}

	return cmd
}
