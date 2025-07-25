package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/ecadlabs/signatory/pkg/vault/confidentialspace"
	"github.com/ecadlabs/signatory/pkg/vault/confidentialspace/rpc"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

// LoadAWSCredentials creates a dummy credentials object for the confidentialspace rpctool
func LoadCredentials(ctx context.Context, conf interface{}) (*rpc.ConfidentialSpaceCredentials, error) {
	return &rpc.ConfidentialSpaceCredentials{}, nil
}

func rpcTool(ip string, port uint64, wipPath string, keyPath string) error {
	cred := rpc.ConfidentialSpaceCredentials{
		WipPath:           wipPath,
		EncryptionKeyPath: keyPath,
	}
	if !cred.IsValid() {
		return errors.New("missing credentials")
	}

	var readLine func() ([]byte, error)

	var err error
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

	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	var conn net.Conn
	log.Printf("Connecting to the enclave signer on %s...\n", addr)
	conn, err = net.Dial("tcp", addr)

	if err != nil {
		return err
	}

	client := rpc.NewClient[rpc.ConfidentialSpaceCredentials](conn)
	defer client.Close()

	log.Printf("Sending credentials to %s...\n", cred)
	if err := client.Initialize(context.Background(), &cred); err != nil {
		return err
	}

	for {
		line, err := readLine()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		var req rpc.Request[rpc.ConfidentialSpaceCredentials]
		if err := json.Unmarshal(line, &req); err != nil {
			fmt.Println(err)
			continue
		}

		res, err := rpc.RoundTripRaw[any](context.Background(), client.Conn(), &req, nil)
		if err != nil {
			return err
		}

		buf, err := json.Marshal(jsonify(res))
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
		ip      string
		port    uint64
		debug   bool
		wipPath string
		keyPath string
	)
	flag.StringVar(&ip, "ip", "", "Enclave IP address (required)")
	flag.Uint64Var(&port, "port", confidentialspace.DefaultPort, "Enclave signer port")
	flag.StringVar(&wipPath, "wip-path", "", "WIP path")
	flag.StringVar(&keyPath, "key-path", "", "Encryption key path")
	flag.BoolVar(&debug, "d", false, "Debug")
	flag.Parse()

	if ip == "" {
		log.Fatal("ip flag is required")
	}

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	if err := rpcTool(ip, port, wipPath, keyPath); err != nil {
		log.Fatal(err)
	}
}
