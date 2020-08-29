/*
 * Copyright 2020 The Hyperledger-TWGC Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* +build cgo */
package gmssl

/*
#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/sms4.h>

static void cb_cipher_names_len(const EVP_CIPHER *cipher, const char *from,
	const char *to, void *x) {
	if (cipher) {
		*((int *)x) += strlen(EVP_CIPHER_name(cipher)) + 1;
	}
}

static void cb_cipher_names(const EVP_CIPHER *cipher, const char *from,
	const char *to, void *x) {
	if (cipher) {
		if (strlen((char *)x) > 0) {
			strcat((char *)x, ":");
		}
		strcat((char *)x, EVP_CIPHER_name(cipher));
	}
}

static char *get_cipher_names(void) {
	char *ret = NULL;
	int len = 0;
	EVP_CIPHER_do_all_sorted(cb_cipher_names_len, &len);
	if (!(ret = OPENSSL_zalloc(len))) {
		return NULL;
	}
	EVP_CIPHER_do_all_sorted(cb_cipher_names, ret);
	return ret;
}

extern void _OPENSSL_free(void *addr);
*/
import "C"

import (
	"errors"
	"runtime"
	"strings"
	"unsafe"
)

func GetCipherNames() []string {
	cnames := C.get_cipher_names()
	defer C._OPENSSL_free(unsafe.Pointer(cnames))
	return strings.Split(C.GoString(cnames), ":")
}

func GetCipherKeyLength(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	cipher := C.EVP_get_cipherbyname(cname)
	if cipher == nil {
		return 0, GetErrors()
	}
	return int(C.EVP_CIPHER_key_length(cipher)), nil
}

func GetCipherBlockLength(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	cipher := C.EVP_get_cipherbyname(cname)
	if cipher == nil {
		return 0, GetErrors()
	}
	return int(C.EVP_CIPHER_block_size(cipher)), nil
}

func GetCipherIVLength(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	cipher := C.EVP_get_cipherbyname(cname)
	if cipher == nil {
		return 0, GetErrors()
	}
	return int(C.EVP_CIPHER_iv_length(cipher)), nil
}

type CipherContext struct {
	ctx *C.EVP_CIPHER_CTX
}

func CipherECBenc(input []byte, key []byte) ([]byte, error) {
	output := make([]byte, 16)

	var sms4_key C.sms4_key_t
	C.sms4_set_encrypt_key(&sms4_key, (*C.uchar)(&key[0]))
	C.sms4_encrypt((*C.uchar)(&input[0]), (*C.uchar)(&output[0]), &sms4_key)
	return output[:16], nil
}
func CipherECBdec(input []byte, key []byte) ([]byte, error) {
	output := make([]byte, 16)
	var sms4_key C.sms4_key_t
	C.sms4_set_decrypt_key(&sms4_key, (*C.uchar)(&key[0]))
	C.sms4_encrypt((*C.uchar)(&input[0]), (*C.uchar)(&output[0]), &sms4_key)
	return output[:16], nil
}
func NewCipherContext(name string, key, iv []byte, encrypt bool) (
	*CipherContext, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	cipher := C.EVP_get_cipherbyname(cname)
	if cipher == nil {
		return nil, GetErrors()
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
		return nil, GetErrors()
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
		return nil, GetErrors()
	}
	return ret, nil
}

func (ctx *CipherContext) Update(in []byte) ([]byte, error) {
	outbuf := make([]byte, len(in)+int(C.EVP_CIPHER_CTX_block_size(ctx.ctx)))
	outlen := C.int(len(outbuf))
	if 1 != C.EVP_CipherUpdate(ctx.ctx, (*C.uchar)(&outbuf[0]), &outlen,
		(*C.uchar)(&in[0]), C.int(len(in))) {
		return nil, GetErrors()
	}
	return outbuf[:outlen], nil
}

func (ctx *CipherContext) Final() ([]byte, error) {
	outbuf := make([]byte, int(C.EVP_CIPHER_CTX_block_size(ctx.ctx)))
	outlen := C.int(len(outbuf))
	if 1 != C.EVP_CipherFinal(ctx.ctx, (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, GetErrors()
	}
	return outbuf[:outlen], nil
}
