package main

import (
	"encoding/hex"
	"fmt"

	"github.com/ecadlabs/gotez"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/spf13/cobra"
)

func NewAuthRequestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authenticate <secret key> <request pkh> <request body>",
		Short: "Authenticate (sign) a sign request",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			priv, err := utils.ParsePrivateKey([]byte(args[0]))
			if err != nil {
				return err
			}

			msg, err := hex.DecodeString(args[2])
			if err != nil {
				return err
			}

			req := signatory.SignRequest{
				Message:       msg,
				PublicKeyHash: args[1],
			}

			data, err := signatory.AuthenticatedBytesToSign(&req)
			if err != nil {
				return err
			}

			sig, err := cryptoutils.Sign(priv, data)
			if err != nil {
				return err
			}

			tzSig, err := gotez.NewSignature(sig)
			if err != nil {
				return err
			}
			res := tzSig.String()
			fmt.Println(res)
			return nil
		},
	}

	return cmd
}
