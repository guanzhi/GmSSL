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

func GetDigestNames() []string {
	return []string{
		"BLAKE2b512",
		"BLAKE2s256",
		"MD4",
		"MD5",
		"MD5-SHA1",
		"MDC2",
		"RIPEMD160",
		"rmd160",
		"SHA1",
		"SHA224",
		"SHA256",
		"SHA384",
		"SHA512",
		"SM3",
		"SHA1",
		"SHA224",
		"SHA256",
		"SHA384",
		"SHA512",
		"SM3",
		"whirlpool",
	}
}

func GetDigestLength(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	md := C.EVP_get_digestbyname(cname)
	if md == nil {
		return 0, errors.New("Invalid digest name")
	}
	return int(C.EVP_MD_size(md)), nil
}

type DigestContext struct {
	ctx *C.EVP_MD_CTX
}

func NewDigestContext(name string, eng *Engine) (*DigestContext, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	md := C.EVP_get_digestbyname(cname)
	if md == nil {
		return nil, fmt.Errorf("shit")
	}

	ctx := C.EVP_MD_CTX_new()
	if ctx == nil {
		return nil, fmt.Errorf("shit")
	}

	ret := &DigestContext{ctx}
	runtime.SetFinalizer(ret, func(ret *DigestContext) {
		C.EVP_MD_CTX_free(ret.ctx)
	})

	if 1 != C.EVP_DigestInit(ctx, md) {
		return nil, fmt.Errorf("shit")
	}

	return ret, nil
}

func (ctx *DigestContext) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if 1 != C.EVP_DigestUpdate(ctx.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) {
		errors.New("hello")
	}
	return nil
}

func (ctx *DigestContext) Final() ([]byte, error) {
	outbuf := make([]byte, 64)
	outlen := C.uint(len(outbuf))
	if 1 != C.EVP_DigestFinal(ctx.ctx, (*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
		return nil, errors.New("error")
	}
	return outbuf[:outlen], nil
}
