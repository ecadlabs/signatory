package main

import (
	"os"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "signatory-tools",
		Short: "Various Signatory tools",
	}

	rootCmd.AddCommand(NewGenKeyCommand())
	rootCmd.AddCommand(NewAuthRequestCommand())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
