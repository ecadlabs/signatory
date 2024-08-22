//go:build darwin

package cryptokit

/*
#cgo LDFLAGS: -Lmacos/.build/release/ -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/macosx/ -L/Library/Developer/CommandLineTools/usr/lib/swift/macosx -lmacos

#include <stdbool.h>

int cryptoKitErrorGetCode(void const *ptr);
int cryptoKitErrorGetUnderlyingCoreCryptoError(void const *ptr);
void dataGetBytes(void const *from, void *to);
int dataGetCount(void const *from);
void deallocate(void *ptr);
bool isAvailable(void);

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
	"fmt"
	"runtime"
	"unsafe"
)

const (
	ErrCodeIncorrectKeySize = iota
	ErrCodeIncorrectParameterSize
	ErrCodeAuthenticationFailure
	ErrCodeUnderlyingCoreCryptoError
	ErrCodeWrapFailure
	ErrCodeUnwrapFailure
	ErrCodeInvalidParameter
	ErrCodeUnknown = -1
)

type Error struct {
	ErrorCode                 int
	UnderlyingCoreCryptoError int
}

func (err Error) Error() string {
	switch err.ErrorCode {
	case ErrCodeIncorrectKeySize:
		return "incorrect key size"
	case ErrCodeIncorrectParameterSize:
		return "incorrect parameter size"
	case ErrCodeAuthenticationFailure:
		return "authentication failure"
	case ErrCodeUnderlyingCoreCryptoError:
		return fmt.Sprintf("underlying core crypto error: %d", err.UnderlyingCoreCryptoError)
	case ErrCodeWrapFailure:
		return "wrap failure"
	case ErrCodeUnwrapFailure:
		return "unwrap failure"
	case ErrCodeInvalidParameter:
		return "invalid parameter"
	default:
		return "unknown"
	}
}

func IsAvailable() bool {
	return bool(C.isAvailable())
}

type PrivateKey struct {
	ptr unsafe.Pointer
}

func makeError(res unsafe.Pointer) *Error {
	err := Error{ErrorCode: ErrCodeUnknown}
	if res != nil {
		if err.ErrorCode = int(C.cryptoKitErrorGetCode(res)); err.ErrorCode == ErrCodeUnderlyingCoreCryptoError {
			err.UnderlyingCoreCryptoError = int(C.cryptoKitErrorGetUnderlyingCoreCryptoError(res))
		}
		C.deallocate(res)
	}
	return &err
}

func NewPrivateKey() (*PrivateKey, error) {
	var errResult unsafe.Pointer
	result := C.newPrivateKey(unsafe.Pointer(&errResult))
	if result == nil {
		return nil, makeError(errResult)
	}
	key := &PrivateKey{ptr: result}
	runtime.SetFinalizer(key, func(x *PrivateKey) { C.deallocate(x.ptr) })
	return key, nil
}

func NewPrivateKeyFromData(data []byte) (*PrivateKey, error) {
	var errResult unsafe.Pointer
	result := C.newPrivateKeyFromData(unsafe.Pointer(&data[0]), C.int(len(data)), unsafe.Pointer(&errResult))
	if result == nil {
		return nil, makeError(errResult)
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
		return nil, makeError(errResult)
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
