/* +build cgo */
package gmssl

/*
#include <openssl/evp.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

func GetCiphers(aliases bool) []string {
	return []string{"sms4-cbc", "aes-128-cbc", "aes-256-cbc"}
}

func GetCipherKeyLength(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	cipher := C.EVP_get_cipherbyname(cname)
	if cipher == nil {
		return 0, errors.New("Invalid cipher name")
	}
	return int(C.EVP_CIPHER_key_length(cipher)), nil
}

func GetCipherBlockSize(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	cipher := C.EVP_get_cipherbyname(cname)
	if cipher == nil {
		return 0, errors.New("Invalid cipher")
	}
	return int(C.EVP_CIPHER_block_size(cipher)), nil
}

func GetCipherIVLength(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	cipher := C.EVP_get_cipherbyname(cname)
	if cipher == nil {
		return 0, errors.New("Invalid cipher")
	}
	return int(C.EVP_CIPHER_iv_length(cipher)), nil
}

type CipherContext struct {
	ctx *C.EVP_CIPHER_CTX
}

func NewCipherContext(name string, args map[string]string, key, iv []byte, encrypt bool) (
	*CipherContext, error) {

	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	cipher := C.EVP_get_cipherbyname(cname)
	if cipher == nil {
		return nil, fmt.Errorf("shit")
	}

	if key == nil {
		return nil, errors.New("No key")
	}
	if len(key) != int(C.EVP_CIPHER_key_length(cipher)) {
		return nil, errors.New("Invalid key length")
	}

	if 0 != int(C.EVP_CIPHER_iv_length(cipher)) {
		if iv == nil {
			return nil, errors.New("No IV")
		}
		if len(iv) != int(C.EVP_CIPHER_iv_length(cipher)) {
			return nil, errors.New("Invalid IV")
		}
	}

	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, fmt.Errorf("shit")
	}

	ret := &CipherContext{ctx}
	runtime.SetFinalizer(ret, func(ret *CipherContext) {
		C.EVP_CIPHER_CTX_free(ret.ctx)
	})

	enc := 1
	if encrypt == false {
		enc = 0
	}

	if 1 != C.EVP_CipherInit(ctx, cipher, (*C.uchar)(&key[0]),
		(*C.uchar)(&iv[0]), C.int(enc)) {
		return nil, fmt.Errorf("shit")
	}

	return ret, nil
}

func (ctx *CipherContext) Update(in []byte) ([]byte, error) {
	outbuf := make([]byte, len(in)+int(C.EVP_CIPHER_CTX_block_size(ctx.ctx)))
	outlen := C.int(len(outbuf))
	if 1 != C.EVP_CipherUpdate(ctx.ctx, (*C.uchar)(&outbuf[0]), &outlen,
		(*C.uchar)(&in[0]), C.int(len(in))) {
		return nil, fmt.Errorf("failed to decrypt")
	}
	return outbuf[:outlen], nil
}

func (ctx *CipherContext) Final() ([]byte, error) {
	outbuf := make([]byte, int(C.EVP_CIPHER_CTX_block_size(ctx.ctx)))
	outlen := C.int(len(outbuf))
	if 1 != C.EVP_CipherFinal(ctx.ctx, (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, fmt.Errorf("failed to decrypt")
	}
	return outbuf[:outlen], nil
}
