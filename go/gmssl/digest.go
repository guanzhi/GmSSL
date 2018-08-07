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
#include <openssl/err.h>
#include <openssl/crypto.h>

static void cb_digest_names_len(const EVP_MD *md, const char *from,
	const char *to,
	void *x) {
	if (md) {
		*((int *)x) += strlen(EVP_MD_name(md)) + 1;
	}
}

static void cb_digest_names(const EVP_MD *md, const char *from,
	const char *to, void *x) {
	if (md) {
		if (strlen((char *)x) > 0) {
			strcat((char *)x, ":");
		}
		strcat((char *)x, EVP_MD_name(md));
	}
}

static char *get_digest_names() {
	char *ret = NULL;
	int len = 0;
	EVP_MD_do_all_sorted(cb_digest_names_len, &len);
	if (!(ret = OPENSSL_zalloc(len))) {
		return NULL;
	}
	EVP_MD_do_all_sorted(cb_digest_names, ret);
	return ret;
}

extern void _OPENSSL_free(void *addr);
*/
import "C"

import (
	"unsafe"
	"runtime"
	"strings"
)

func GetDigestNames() []string {
	cnames := C.get_digest_names()
	defer C._OPENSSL_free(unsafe.Pointer(cnames))
	return strings.Split(C.GoString(cnames), ":")
}

func GetDigestLength(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	md := C.EVP_get_digestbyname(cname)
	if md == nil {
		return 0, GetErrors()
	}
	return int(C.EVP_MD_size(md)), nil
}

func GetDigestBlockSize(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	md := C.EVP_get_digestbyname(cname)
	if md == nil {
		return 0, GetErrors()
	}
	return int(C.EVP_MD_block_size(md)), nil
}

type DigestContext struct {
	ctx *C.EVP_MD_CTX
}

func NewDigestContext(name string) (*DigestContext, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	md := C.EVP_get_digestbyname(cname)
	if md == nil {
		return nil, GetErrors()
	}
	ctx := C.EVP_MD_CTX_new()
	if ctx == nil {
		return nil, GetErrors()
	}
	ret := &DigestContext{ctx}
	runtime.SetFinalizer(ret, func(ret *DigestContext) {
		C.EVP_MD_CTX_free(ret.ctx)
	})
	if 1 != C.EVP_DigestInit_ex(ctx, md, nil) {
		return nil, GetErrors()
	}
	return ret, nil
}

func (ctx *DigestContext) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if 1 != C.EVP_DigestUpdate(ctx.ctx, unsafe.Pointer(&data[0]),
		C.size_t(len(data))) {
		return GetErrors()
	}
	return nil
}

func (ctx *DigestContext) Final() ([]byte, error) {
	outbuf := make([]byte, 64)
	outlen := C.uint(len(outbuf))
	if 1 != C.EVP_DigestFinal_ex(ctx.ctx,
		(*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
		return nil, GetErrors()
	}
	return outbuf[:outlen], nil
}

func (ctx *DigestContext) Reset() error {
	md := C.EVP_MD_CTX_md(ctx.ctx)
	if md == nil {
		return GetErrors() //FIXME: return some errors
	}
	if 1 != C.EVP_DigestInit_ex(ctx.ctx, md, nil) {
		return GetErrors()
	}
	return nil
}
