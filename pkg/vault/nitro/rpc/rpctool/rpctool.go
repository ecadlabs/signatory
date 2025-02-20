package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ecadlabs/signatory/pkg/vault/nitro"
	"github.com/ecadlabs/signatory/pkg/vault/nitro/rpc"
	"github.com/ecadlabs/signatory/pkg/vault/nitro/rpc/vsock"
	"github.com/kr/pretty"
	"golang.org/x/term"
)

type logFunc func(format string, args ...interface{}) (int, error)

func (l logFunc) Debugf(format string, args ...interface{}) { l(format, args) }

func rpcTool(cid, port uint64, keyID string, logger rpc.Logger) error {
	cred, err := rpc.LoadAWSCredentials(context.Background(), nil)
	if err != nil {
		return err
	}
	if keyID != "" {
		cred.EncryptionKeyID = keyID
	}
	if !cred.IsValid() {
		return errors.New("missing credentials")
	}

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
		return nil
	}

	client := rpc.NewClient[rpc.AWSCredentials](conn, nil)
	defer client.Close()

	fmt.Println("Sending credentials...")
	if err := client.Initialize(context.Background(), cred); err != nil {
		return nil
	}

	for {
		line, err := readLine()
		if err != nil {
			if err != io.EOF {
				return err
			}
			return nil
		}
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		var req rpc.Request[rpc.AWSCredentials]
		if err := json.Unmarshal(line, &req); err != nil {
			fmt.Println(err)
			continue
		}

		res, err := rpc.RoundTripRaw[any](context.Background(), client.Conn(), &req, logger)
		if err != nil {
			return err
		}

		if logger != nil {
			logger.Debugf("%# v", pretty.Formatter(res))
		}

		buf, err := json.MarshalIndent(jsonify(res), "", "    ")
		if err != nil {
			return err
		}

		fmt.Println(string(buf))
	}
}

// transform map[any]any as returned by CBOR codec into JSON-appropriate map[string]any
func jsonify(src any) any {
	switch x := src.(type) {
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, v := range x {
			out[fmt.Sprint(k)] = jsonify(v)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = jsonify(v)
		}
		return out
	default:
		return src
	}
}

func main() {
	var (
		cid, port uint64
		debug     bool
		keyID     string
	)
	flag.Uint64Var(&cid, "cid", nitro.DefaultCID, "Enclave CID")
	flag.Uint64Var(&port, "port", nitro.DefaultPort, "Enclave signer port")
	flag.StringVar(&keyID, "key-id", "", "Encryption key ID")
	flag.BoolVar(&debug, "d", false, "Debug")
	flag.Parse()

	var logger rpc.Logger
	if debug {
		logger = logFunc(fmt.Printf)
	}
	if err := rpcTool(cid, port, keyID, logger); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
