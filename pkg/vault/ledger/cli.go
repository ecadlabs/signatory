package ledger

import (
	"fmt"
	"html/template"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

const listTemplateSrc = `{{range . -}}
Path:  		{{.Path}}
ID:     	{{.ID}} / {{.ShortID}}
PKH:		{{.Pkh}}
Version:	{{.Version}}
{{end}}
`

var listTpl = template.Must(template.New("list").Parse(listTemplateSrc))

func newListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List connected Ledgers",
		RunE: func(cmd *cobra.Command, args []string) error {
			devs, err := deviceScanner.scan()
			if err != nil {
				return err
			}
			return listTpl.Execute(os.Stdout, devs)
		},
	}
}

func newSetupCommand() *cobra.Command {
	var (
		id      string
		mainHWM uint32
		testHWM uint32
		chainID string
	)

	cmd := cobra.Command{
		Use:   "setup-baking <key id>",
		Short: "Authorize a key for baking",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pkh, err := SetupBaking(id, args[0], chainID, mainHWM, testHWM)
			if err != nil {
				return err
			}
			fmt.Printf("Authorized baking for address: %s\n", pkh)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&id, "device", "d", "", "Ledger device ID")
	f.Uint32Var(&mainHWM, "main-hwm", 0, "Main high water mark")
	f.Uint32Var(&testHWM, "test-hwm", 0, "Test high water mark")
	f.StringVar(&chainID, "chain-id", "", "Chain ID")
	return &cmd
}

func newDeuthorizeCommand() *cobra.Command {
	var id string
	cmd := cobra.Command{
		Use:   "deauthorize-baking <key id>",
		Short: "Deuthorize a key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return DeauthorizeBaking(id)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&id, "device", "d", "", "Ledger device ID")
	return &cmd
}

func newSetHighWatermarkCommand() *cobra.Command {
	var id string
	cmd := cobra.Command{
		Use:   "set-high-watermark <hwm>",
		Short: "Set high water mark",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hwm, _ := strconv.ParseUint(args[0], 10, 32)
			return SetHighWatermark(id, uint32(hwm))
		},
	}
	f := cmd.Flags()
	f.StringVarP(&id, "device", "d", "", "Ledger device ID")
	return &cmd
}

func newGetHighWatermarkCommand() *cobra.Command {
	var id string
	cmd := cobra.Command{
		Use:   "get-high-watermark",
		Short: "Get high water mark",
		RunE: func(cmd *cobra.Command, args []string) error {
			hwm, err := GetHighWatermark(id)
			if err != nil {
				return err
			}
			fmt.Println(hwm)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&id, "device", "d", "", "Ledger device ID")
	return &cmd
}

func newGetHighWatermarksCommand() *cobra.Command {
	var id string
	cmd := cobra.Command{
		Use:   "get-high-watermarks",
		Short: "Get all high water marks and chain ID",
		RunE: func(cmd *cobra.Command, args []string) error {
			mainHWM, testHWM, chainID, err := GetHighWatermarks(id)
			if err != nil {
				return err
			}
			fmt.Printf("Main: %d\nTest: %d\nChain ID: %s\n", mainHWM, testHWM, chainID)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&id, "device", "d", "", "Ledger device ID")
	return &cmd
}

func newLedgerCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "ledger",
		Short: "Ledger specific operations",
	}

	cmd.AddCommand(newListCommand())
	cmd.AddCommand(newSetupCommand())
	cmd.AddCommand(newDeuthorizeCommand())
	cmd.AddCommand(newSetHighWatermarkCommand())
	cmd.AddCommand(newGetHighWatermarkCommand())
	cmd.AddCommand(newGetHighWatermarksCommand())

	return &cmd
}
