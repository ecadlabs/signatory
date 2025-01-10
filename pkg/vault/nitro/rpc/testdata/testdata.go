package testdata

import _ "embed"

//go:embed reply_generate_and_import.bin
var ReplyGenerateAndImport []byte

//go:embed reply_generate_bls.bin
var ReplyGenerateBls []byte

//go:embed reply_generate_ed.bin
var ReplyGenerateEd []byte

//go:embed reply_generate_nist.bin
var ReplyGenerateNist []byte

//go:embed reply_generate_secp.bin
var ReplyGenerateSecp []byte

//go:embed reply_import_ed_ok.bin
var ReplyImportEdOk []byte

//go:embed reply_import_err.bin
var ReplyImportErr []byte

//go:embed reply_ok.bin
var ReplyOk []byte

//go:embed reply_try_sign_bls.bin
var ReplyTrySignBls []byte

//go:embed reply_try_sign_ed.bin
var ReplyTrySignEd []byte

//go:embed reply_try_sign_nist.bin
var ReplyTrySignNist []byte

//go:embed request_generate.bin
var RequestGenerate []byte

//go:embed request_generate_and_import.bin
var RequestGenerateAndImport []byte

//go:embed request_import.bin
var RequestImport []byte

//go:embed request_initialize.bin
var RequestInitialize []byte

//go:embed request_public_key.bin
var RequestPublicKey []byte

//go:embed request_public_key_from.bin
var RequestPublicKeyFrom []byte

//go:embed request_sign.bin
var RequestSign []byte

//go:embed request_sign_with.bin
var RequestSignWith []byte

//go:embed request_terminate.bin
var RequestTerminate []byte
