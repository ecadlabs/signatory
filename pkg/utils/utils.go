package utils

import (
	"crypto"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/ecadlabs/gotez"
	"github.com/ecadlabs/gotez/b58"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"golang.org/x/term"
)

var (
	errRune   = errors.New("invalid rune")
	errQuoted = errors.New("unexpected end of the quoted string")
	errEOF    = errors.New("unexpected end of the string")
)

func readString(p []byte, end rune) (rem []byte, out string, err error) {
	r, sz := utf8.DecodeRune(p)
	if r == utf8.RuneError {
		return nil, "", errRune
	}
	p = p[sz:]

	var (
		quoted bool
		qRune  rune
		o      strings.Builder
	)
	if r == '\'' || r == '"' {
		quoted = true
		qRune = r
	} else {
		o.WriteRune(r)
	}

	var esc bool
	for {
		if len(p) == 0 {
			if quoted || esc {
				return nil, "", errQuoted
			}
			return p, o.String(), nil
		}

		r, sz := utf8.DecodeRune(p)
		if r == utf8.RuneError {
			return nil, "", errRune
		}

		if !esc && !quoted && (r == end || unicode.IsSpace(r)) {
			return p, o.String(), nil
		}
		p = p[sz:]

		switch {
		case esc:
			o.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case quoted && r == qRune:
			return p, o.String(), nil
		default:
			o.WriteRune(r)
		}
	}
}

func eatSpace(p []byte) (rem []byte, err error) {
	for len(p) != 0 {
		r, sz := utf8.DecodeRune(p)
		if r == utf8.RuneError {
			return nil, errRune
		}
		if !unicode.IsSpace(r) {
			break
		}
		p = p[sz:]
	}
	return p, nil
}

// ParseMap returns parsed key/val map
func ParseMap(s string, namevalSep, tuplesSep rune) (res map[string]string, err error) {
	res = make(map[string]string)
	p := []byte(s)
	for {
		p, err = eatSpace(p)
		if err != nil {
			return nil, err
		}
		if len(p) == 0 {
			break
		}

		var name, val string
		p, name, err = readString(p, namevalSep)
		if err != nil {
			return nil, err
		}
		p, err = eatSpace(p)
		if err != nil {
			return nil, err
		}
		if namevalSep >= 0 {
			r, sz := utf8.DecodeRune(p)
			if r == utf8.RuneError {
				return nil, errRune
			}
			p = p[sz:]
			if r != namevalSep {
				return nil, fmt.Errorf("unexpected character: %c", r)
			}
			p, err = eatSpace(p)
			if err != nil {
				return nil, err
			}
		}
		p, val, err = readString(p, tuplesSep)
		if err != nil {
			return nil, err
		}
		res[name] = val

		if tuplesSep >= 0 {
			p, err = eatSpace(p)
			if err != nil {
				return nil, err
			}
			if len(p) == 0 {
				break
			}
			r, sz := utf8.DecodeRune(p)
			if r == utf8.RuneError {
				return nil, errRune
			}
			p = p[sz:]
			if r != tuplesSep {
				return nil, fmt.Errorf("unexpected character: %c", r)
			}
			p, err = eatSpace(p)
			if err != nil {
				return nil, err
			}
			if len(p) == 0 {
				return nil, errEOF
			}
		}
	}
	return res, nil
}

func KeyboardInteractivePassphraseFunc(prompt string) func() ([]byte, error) {
	return func() ([]byte, error) {
		fmt.Print(prompt)
		defer fmt.Println()
		return term.ReadPassword(int(syscall.Stdin))
	}
}

func EncodePublicKeyHash(pub crypto.PublicKey) (string, error) {
	p, err := gotez.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	return p.Hash().String(), nil
}

func EncodePrivateKey(priv cryptoutils.PrivateKey) (string, error) {
	p, err := gotez.NewPrivateKey(priv)
	if err != nil {
		return "", err
	}
	return p.String(), nil
}

func EncodePublicKey(pub crypto.PublicKey) (string, error) {
	p, err := gotez.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	return p.String(), nil
}

func EncodeSignature(sig cryptoutils.Signature) (string, error) {
	p, err := gotez.NewSignature(sig)
	if err != nil {
		return "", err
	}
	return p.String(), nil
}

func ParsePublicKey(src []byte) (crypto.PublicKey, error) {
	pub, err := b58.ParsePublicKey(src)
	if err != nil {
		return nil, err
	}
	return pub.PublicKey()
}

func ParsePrivateKey(src []byte) (cryptoutils.PrivateKey, error) {
	priv, err := b58.ParsePrivateKey(src)
	if err != nil {
		return nil, err
	}
	return priv.PrivateKey()
}
