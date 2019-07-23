package main

import (
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ecadlabs/signatory/pkg/metrics"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/manifoldco/promptui"
	log "github.com/sirupsen/logrus"
)

type mergeEntry struct {
	PK pkEntry
	SK skEntry
}

type skEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type pkEntry struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}

func (s *mergeEntry) IsUnencrypted() bool {
	return strings.HasPrefix(s.SK.Value, "unencrypted")
}

func (s *mergeEntry) SecretKey() string {
	reg := regexp.MustCompile(`.*:(.*)`)
	return reg.FindStringSubmatch(s.SK.Value)[1]
}

func (s *mergeEntry) PublicKey() string {
	if val, ok := s.PK.Value.(string); ok {
		reg := regexp.MustCompile(`.*:(.*)`)
		return reg.FindStringSubmatch(val)[1]
	} else if keyObj, ok := s.PK.Value.(map[string]interface{}); ok {
		if val, ok := keyObj["key"].(string); ok {
			return val
		}
	}
	panic("Unkown key format")
}

func (s *mergeEntry) KeyPair() *tezos.KeyPair {
	return tezos.NewKeyPair(s.PublicKey(), s.SecretKey())
}

func (s *mergeEntry) PKH() string {
	pkh, _ := s.KeyPair().PubKeyHash()
	return pkh
}

func (s *mergeEntry) CompleteName() string {
	return fmt.Sprintf("%s: (%s)", s.Name(), s.PKH())
}

func (s *mergeEntry) Name() string {
	return s.PK.Name
}

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func main() {
	var tezosFile string
	var keyToExport string
	var output string
	var version bool
	flag.StringVar(&tezosFile, "f", "~/.tezos-client", "Path to your unencrypted wallet file")
	flag.StringVar(&output, "o", "", `File path of your exported key (default "./<NAME_OF_YOUR_KEY")`)
	flag.BoolVar(&version, "v", false, "Print the version")
	flag.StringVar(&keyToExport, "key", "", "Name of the key to export (optional)")
	flag.Parse()

	if version {
		log.Infof("Git version: %s", metrics.GitVersion)
		log.Infof("Git revision: %s", metrics.GitRevision)
		log.Infof("Git branch: %s", metrics.GitBranch)
		os.Exit(0)
	}

	f, err := os.Open(filepath.Join(tezosFile, "secret_keys"))
	check(err)

	skEntries := []skEntry{}

	err = json.NewDecoder(f).Decode(&skEntries)
	check(err)

	f, err = os.Open(filepath.Join(tezosFile, "public_keys"))
	check(err)

	pkEntries := []pkEntry{}

	err = json.NewDecoder(f).Decode(&pkEntries)
	check(err)

	mergedEntries := []mergeEntry{}
	var hasUnsupportedKey = false
	for _, sk := range skEntries {
		for _, pk := range pkEntries {
			if pk.Name == sk.Name {
				if !strings.HasPrefix(sk.Value, "unencrypted:edsk") {
					mergedEntries = append(mergedEntries, mergeEntry{
						PK: pk,
						SK: sk,
					})
				} else {
					hasUnsupportedKey = true
				}
			}
		}
	}

	if hasUnsupportedKey {
		log.Warn("Exports of tz1 addresses are not yet supported")
	}

	if keyToExport == "" {
		keyName := []string{}
		for _, key := range mergedEntries {
			if key.IsUnencrypted() {
				keyName = append(keyName, key.CompleteName())
			}
		}

		prompt := promptui.Select{
			Label: "Select Key to export",
			Items: keyName,
		}
		_, result, err := prompt.Run()
		check(err)

		keyToExport = result
	} else {
		for _, key := range mergedEntries {
			if key.Name() == keyToExport {
				keyToExport = key.CompleteName()
			}
		}
	}

	var entryToExport mergeEntry
	for _, entry := range mergedEntries {
		if entry.CompleteName() == keyToExport {
			entryToExport = entry
		}
	}

	x509Encoded, err := entryToExport.KeyPair().EncodeASN1()
	check(err)
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509Encoded,
	}
	var outputFile *os.File
	if output == "" {
		f, err = os.Create(fmt.Sprintf("./%s.pem", entryToExport.Name()))
		check(err)
		defer f.Close()
		outputFile = f
	} else {
		outputFile, err = os.Create(output)
		check(err)
		defer f.Close()
		outputFile = f
	}
	err = pem.Encode(outputFile, block)
	check(err)
	log.Infof("Exported %s to %s succesfully", entryToExport.PKH(), outputFile.Name())
}
