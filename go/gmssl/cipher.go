/*
 * Copyright (c) 2017 - 2018 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* +build cgo */
package gmssl

/*
#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

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
	"unsafe"
	"runtime"
	"strings"
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
