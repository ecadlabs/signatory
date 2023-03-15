package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/ecadlabs/gotez"
	"github.com/ecadlabs/signatory/cmd/approve-list-svc/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "approve-list-svc",
	Short: "Example IP approve list external policy service",
}

var confFile string

var pubCmd = &cobra.Command{
	Use:   "pub",
	Short: "Print the authentication public key",
	RunE: func(cmd *cobra.Command, args []string) error {
		conf, err := ReadConfig(confFile)
		if err != nil {
			return err
		}
		pk, err := conf.GetPrivateKey()
		if err != nil {
			return err
		}
		if pk == nil {
			return errors.New("private key is not specified")
		}

		pub, err := gotez.NewPublicKey(pk.Public())
		if err != nil {
			return err
		}

		fmt.Printf("Public key: %v\n", pub)
		return nil
	},
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the server",
	RunE: func(cmd *cobra.Command, args []string) error {
		conf, err := ReadConfig(confFile)
		if err != nil {
			return err
		}

		pk, err := conf.GetPrivateKey()
		if err != nil {
			return err
		}

		ips, nets, err := conf.Addresses()
		if err != nil {
			return err
		}

		srv := server.Server{
			Address:    conf.Address,
			PrivateKey: pk,
			Addresses:  ips,
			Nets:       nets,
		}

		s := srv.New()
		log.Printf("HTTP server is listening for connections on %s", srv.Address)
		log.Println(s.ListenAndServe())

		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&confFile, "config", "c", "", "Config file")
	rootCmd.AddCommand(pubCmd)
	rootCmd.AddCommand(serveCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
