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
#include <gmssl/hmac.h>
#include <gmssl/cmac.h>
*/
import "C"

import (
	"runtime"
	"unsafe"
)

func GetMacLength(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	md := C.EVP_get_digestbyname(cname)
	if md == nil {
		return 0, GetErrors()
	}
	return int(C.EVP_MD_size(md)), nil
}

type HMACContext struct {
	hctx *C.HMAC_CTX
}

func NewHMACContext(name string, key []byte) (
	*HMACContext, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	md := C.EVP_get_digestbyname(cname)
	if md == nil {
		return nil, GetErrors()
	}
	ctx := C.HMAC_CTX_new()
	if ctx == nil {
		return nil, GetErrors()
	}
	ret := &HMACContext{ctx}
	runtime.SetFinalizer(ret, func(ret *HMACContext) {
		C.HMAC_CTX_free(ret.hctx)
	})
	if 1 != C.HMAC_Init_ex(ctx,
		unsafe.Pointer(&key[0]), C.int(len(key)), md, nil) {
		return nil, GetErrors()
	}
	return ret, nil
}

func (ctx *HMACContext) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if 1 != C.HMAC_Update(ctx.hctx,
		(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) {
		return GetErrors()
	}
	return nil
}

func (ctx *HMACContext) Final() ([]byte, error) {
	outbuf := make([]byte, 64)
	outlen := C.uint(len(outbuf))
	if 1 != C.HMAC_Final(ctx.hctx,
		(*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
		return nil, GetErrors()
	}
	return outbuf[:outlen], nil
}

func (ctx *HMACContext) Reset() error {
	if 1 != C.HMAC_Init_ex(ctx.hctx, nil, 0, nil, nil) {
		return GetErrors()
	}
	return nil
}
