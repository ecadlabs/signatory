package rpc

import "github.com/fxamacker/cbor/v2"

const TerminateRequest = "Terminate"

type Credentials struct {
	AccessKeyID     string  `cbor:"access_key_id"`
	SecretAccessKey string  `cbor:"secret_access_key"`
	SessionToken    *string `cbor:"session_token"`
}

type SignRequest struct {
	Handle uint64 `cbor:"handle"`
	Msg    []byte `cbor:"msg"`
}

type SignWithRequest struct {
	KeyData []byte `cbor:"key_data"`
	Msg     []byte `cbor:"msg"`
}

type Request struct {
	Initialize        *Credentials
	Import            []byte
	Generate          *string
	GenerateAndImport *string
	Sign              *SignRequest
	SignWith          *SignWithRequest
	PublicKey         *uint64
	PublicKeyFrom     []byte
}

type PublicKey struct {
	Secp256k1 []byte
	NistP256  []byte
	Ed25519   []byte
	Bls       []byte
}

type Signature struct {
	Secp256k1 []byte
	NistP256  []byte
	Ed25519   []byte
	Bls       []byte
}

type RPCError struct {
	Message string    `cbor:"message"`
	Source  *RPCError `cbor:"source"`
}

func (e *RPCError) Error() string {
	return e.Message
}

func (e *RPCError) Unwrap() error {
	if e.Source != nil {
		return e.Source
	}
	return nil
}

type ImportResult struct {
	_         struct{} `cbor:",toarray"`
	PublicKey PublicKey
	Handle    uint64
}

type GenerateResult struct {
	_          struct{} `cbor:",toarray"`
	PrivateKey []byte
	PublicKey  PublicKey
}

type GenerateAndImportResult struct {
	_          struct{} `cbor:",toarray"`
	PrivateKey []byte
	PublicKey  PublicKey
	Handle     uint64
}

type Result[T any] struct {
	Ok  *T
	Err *RPCError
}

type SimpleResult struct {
	Ok  cbor.SimpleValue
	Err *RPCError
}
