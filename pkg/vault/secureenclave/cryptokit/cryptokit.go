//go:build darwin

package cryptokit

/*
#cgo LDFLAGS: -Lmacos/.build/release/ -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/macosx/ -L/Library/Developer/CommandLineTools/usr/lib/swift/macosx -lmacos

#include <stdbool.h>

bool isAvailable(void);

int errorGetType(void const *ptr);
void *errorGetCryptoKit(void const *ptr);
void *errorGetCryptoTokenKit(void const *ptr);

int cryptoKitErrorGetType(void const *ptr);
int cryptoKitErrorGetUnderlyingCoreCryptoError(void const *ptr);

int cryptoTokenKitGetCode(void const *ptr);

void dataGetBytes(void const *from, void *to);
int dataGetCount(void const *from);
void deallocate(void *ptr);

void *newPrivateKey(void *error);
void *newPrivateKeyFromData(void const *src, int count, void *error);
void *privateKeyGetDataRepresentation(void const *from);
void *privateKeyGetPublicKey(void const *from);
void *privateKeySignature(void const *from, void const *digest, void *error);

void *publicKeyGetDerRepresentation(void const *from);
void *publicKeyGetRawRepresentation(void const *from);
void *publicKeyGetX963Representation(void const *from);

void *signatureGetDerRepresentation(void const *from);
void *signatureGetRawRepresentation(void const *from);
*/
import "C"
import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

const (
	errorCryptoKit = iota
	errorCryptoTokenKit
)

const (
	cryptoKitErrorIncorrectKeySize = iota
	cryptoKitErrorIncorrectParameterSize
	cryptoKitErrorAuthenticationFailure
	cryptoKitErrorUnderlyingCoreCryptoError
	cryptoKitErrorWrapFailure
	cryptoKitErrorUnwrapFailure
	cryptoKitErrorInvalidParameter
)

const (
	cryptoTokenKitErrorNotImplemented       = -1
	cryptoTokenKitErrorCommunicationError   = -2
	cryptoTokenKitErrorCorruptedData        = -3
	cryptoTokenKitErrorCanceledByUser       = -4
	cryptoTokenKitErrorAuthenticationFailed = -5
	cryptoTokenKitErrorObjectNotFound       = -6
	cryptoTokenKitErrorTokenNotFound        = -7
	cryptoTokenKitErrorBadParameter         = -8
	cryptoTokenKitErrorAuthenticationNeeded = -9
)

var errUnknown = errors.New("cryptokit: unknown error")

type CryptoKitError struct {
	ErrorType                 int
	UnderlyingCoreCryptoError int
}

func (err *CryptoKitError) Error() string {
	switch err.ErrorType {
	case cryptoKitErrorIncorrectKeySize:
		return "cryptokit: incorrect key size"
	case cryptoKitErrorIncorrectParameterSize:
		return "cryptokit: incorrect parameter size"
	case cryptoKitErrorAuthenticationFailure:
		return "cryptokit: authentication failure"
	case cryptoKitErrorUnderlyingCoreCryptoError:
		return fmt.Sprintf("cryptokit: underlying core crypto error: %d", err.UnderlyingCoreCryptoError)
	case cryptoKitErrorWrapFailure:
		return "cryptokit: wrap failure"
	case cryptoKitErrorUnwrapFailure:
		return "cryptokit: unwrap failure"
	case cryptoKitErrorInvalidParameter:
		return "cryptokit: invalid parameter"
	default:
		return "cryptokit: unknown error"
	}
}

type CryptoTokenKitError struct {
	Code int
}

func (err *CryptoTokenKitError) Error() string {
	switch err.Code {
	case cryptoTokenKitErrorNotImplemented:
		return "cryptotokenkit: the functionality is not implemented"
	case cryptoTokenKitErrorCommunicationError:
		return "cryptotokenkit: a communication error occurred"
	case cryptoTokenKitErrorCorruptedData:
		return "cryptotokenkit: the data was corrupted"
	case cryptoTokenKitErrorCanceledByUser:
		return "cryptotokenkit: the operation was canceled by the user"
	case cryptoTokenKitErrorAuthenticationFailed:
		return "cryptotokenkit: authentication failed"
	case cryptoTokenKitErrorObjectNotFound:
		return "cryptotokenkit: the object was not found"
	case cryptoTokenKitErrorTokenNotFound:
		return "cryptotokenkit: the token was not found"
	case cryptoTokenKitErrorBadParameter:
		return "cryptotokenkit: an invalid parameter was provided"
	case cryptoTokenKitErrorAuthenticationNeeded:
		return "cryptotokenkit: authentication is needed"
	default:
		return "cryptotokenkit: unknown error"
	}
}

func IsAvailable() bool {
	return bool(C.isAvailable())
}

type PrivateKey struct {
	ptr unsafe.Pointer
}

func handleError(res unsafe.Pointer) error {
	if res == nil {
		return errUnknown
	}
	defer C.deallocate(res)

	typ := C.errorGetType(res)
	switch typ {
	case errorCryptoKit:
		res := C.errorGetCryptoKit(res)
		defer C.deallocate(res)
		err := CryptoKitError{
			ErrorType: int(C.cryptoKitErrorGetType(res)),
		}
		if err.ErrorType == cryptoKitErrorUnderlyingCoreCryptoError {
			err.UnderlyingCoreCryptoError = int(C.cryptoKitErrorGetUnderlyingCoreCryptoError(res))
		}
		return &err
	case errorCryptoTokenKit:
		res := C.errorGetCryptoTokenKit(res)
		defer C.deallocate(res)
		err := CryptoTokenKitError{
			Code: int(C.cryptoTokenKitGetCode(res)),
		}
		return &err
	default:
		return errUnknown
	}
}

func NewPrivateKey() (*PrivateKey, error) {
	var errResult unsafe.Pointer
	result := C.newPrivateKey(unsafe.Pointer(&errResult))
	if result == nil {
		return nil, handleError(errResult)
	}
	key := &PrivateKey{ptr: result}
	runtime.SetFinalizer(key, func(x *PrivateKey) { C.deallocate(x.ptr) })
	return key, nil
}

func NewPrivateKeyFromData(data []byte) (*PrivateKey, error) {
	var errResult unsafe.Pointer
	result := C.newPrivateKeyFromData(unsafe.Pointer(&data[0]), C.int(len(data)), unsafe.Pointer(&errResult))
	if result == nil {
		return nil, handleError(errResult)
	}
	key := &PrivateKey{ptr: result}
	runtime.SetFinalizer(key, func(x *PrivateKey) { C.deallocate(x.ptr) })
	return key, nil
}

func (priv *PrivateKey) Bytes() []byte {
	data := C.privateKeyGetDataRepresentation(priv.ptr)
	defer C.deallocate(data)
	ln := C.dataGetCount(data)
	buf := make([]byte, ln)
	C.dataGetBytes(data, unsafe.Pointer(&buf[0]))
	return buf
}

type PublicKey struct {
	ptr unsafe.Pointer
}

func (p *PrivateKey) Public() *PublicKey {
	result := C.privateKeyGetPublicKey(p.ptr)
	pub := &PublicKey{ptr: result}
	runtime.SetFinalizer(pub, func(x *PublicKey) { C.deallocate(x.ptr) })
	return pub
}

func (pub *PublicKey) X963Bytes() []byte {
	data := C.publicKeyGetX963Representation(pub.ptr)
	defer C.deallocate(data)
	ln := C.dataGetCount(data)
	buf := make([]byte, ln)
	C.dataGetBytes(data, unsafe.Pointer(&buf[0]))
	return buf
}

func (pub *PublicKey) DERBytes() []byte {
	data := C.publicKeyGetDerRepresentation(pub.ptr)
	defer C.deallocate(data)
	ln := C.dataGetCount(data)
	buf := make([]byte, ln)
	C.dataGetBytes(data, unsafe.Pointer(&buf[0]))
	return buf
}

func (pub *PublicKey) RawBytes() []byte {
	data := C.publicKeyGetRawRepresentation(pub.ptr)
	defer C.deallocate(data)
	ln := C.dataGetCount(data)
	buf := make([]byte, ln)
	C.dataGetBytes(data, unsafe.Pointer(&buf[0]))
	return buf
}

type Signature struct {
	ptr unsafe.Pointer
}

func (p *PrivateKey) Signature(digest *[32]byte) (*Signature, error) {
	var errResult unsafe.Pointer
	dptr := &digest[0]
	result := C.privateKeySignature(p.ptr, unsafe.Pointer(dptr), unsafe.Pointer(&errResult))
	if result == nil {
		return nil, handleError(errResult)
	}
	sig := &Signature{ptr: result}
	runtime.SetFinalizer(sig, func(x *Signature) { C.deallocate(x.ptr) })
	return sig, nil
}

func (sig *Signature) RawBytes() []byte {
	data := C.signatureGetRawRepresentation(sig.ptr)
	defer C.deallocate(data)
	ln := C.dataGetCount(data)
	buf := make([]byte, ln)
	C.dataGetBytes(data, unsafe.Pointer(&buf[0]))
	return buf
}

func (sig *Signature) DERBytes() []byte {
	data := C.signatureGetDerRepresentation(sig.ptr)
	defer C.deallocate(data)
	ln := C.dataGetCount(data)
	buf := make([]byte, ln)
	C.dataGetBytes(data, unsafe.Pointer(&buf[0]))
	return buf
}
