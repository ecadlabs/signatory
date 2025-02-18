package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ecadlabs/signatory/pkg/vault/nitro"
	"github.com/ecadlabs/signatory/pkg/vault/nitro/rpc"
	"github.com/ecadlabs/signatory/pkg/vault/nitro/rpc/vsock"
	"golang.org/x/term"
)

type logFunc func(format string, args ...interface{}) (int, error)

func (l logFunc) Debugf(format string, args ...interface{}) { l(format, args) }

func main() {
	var (
		cid, port uint64
		debug     bool
	)
	flag.Uint64Var(&cid, "cid", nitro.DefaultCID, "Enclave CID")
	flag.Uint64Var(&port, "port", nitro.DefaultPort, "Enclave signer port")
	flag.BoolVar(&debug, "d", false, "Debug")
	flag.Parse()

	var readLine func() ([]byte, error)

	if term.IsTerminal(int(os.Stdin.Fd())) {
		stdio := struct {
			io.Reader
			io.Writer
		}{os.Stdin, os.Stdout}
		trm := term.NewTerminal(stdio, "> ")
		readLine = func() ([]byte, error) {
			oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
			if err != nil {
				return nil, err
			}
			defer term.Restore(int(os.Stdin.Fd()), oldState)
			line, err := trm.ReadLine()
			return []byte(line), err
		}
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		readLine = func() ([]byte, error) {
			if scanner.Scan() {
				return scanner.Bytes(), nil
			}
			if err := scanner.Err(); err != nil {
				return nil, err
			}
			return nil, io.EOF
		}
	}

	addr := vsock.Addr{CID: uint32(cid), Port: uint32(port)}
	fmt.Printf("Connecting to the enclave signer on %v...\n", &addr)
	conn, err := vsock.Dial(&addr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer conn.Close()

	for {
		line, err := readLine()
		if err != nil {
			if err != io.EOF {
				fmt.Println(err)
				os.Exit(1)
			}
			return
		}
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		var req rpc.Request[rpc.AWSCredentials]
		if err := json.Unmarshal(line, &req); err != nil {
			fmt.Println(err)
			continue
		}

		res, err := rpc.RoundTripRaw[any](context.Background(), conn, &req, logFunc(fmt.Printf))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		buf, err := json.MarshalIndent(res, "", "    ")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println(string(buf))
	}
}
