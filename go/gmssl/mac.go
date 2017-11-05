/* +build cgo */

package gmssl

/*
#include <openssl/hmac.h>
#include <openssl/cmac.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

func GetMacNames(aliases bool) []string {
	return []string{
		"HMAC-BLAKE2b512",
		"HMAC-BLAKE2s256",
		"HMAC-MD4",
		"HMAC-MD5",
		"HMAC-MD5-SHA1",
		"HMAC-MDC2",
		"HMAC-RIPEMD160",
		"HMAC-rmd160",
		"HMAC-SHA1",
		"HMAC-SHA224",
		"HMAC-SHA256",
		"HMAC-SHA384",
		"HMAC-SHA512",
		"HMAC-SM3",
		"HMAC-SHA1",
		"HMAC-SHA224",
		"HMAC-SHA256",
		"HMAC-SHA384",
		"HMAC-SHA512",
		"HMAC-SM3",
		"HMAC-whirlpool",
	}
}

func GetMacKeyLength(name string) (int, error) {
	return 0, nil
}

func GetMacLength(name string) (int, error) {
	return 0, nil
}

type MACContext struct {
	hctx *C.HMAC_CTX
}

func NewMACContext(name string, eng *Engine, key []byte) (*MACContext, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	md := C.EVP_get_digestbyname(cname)
	if md == nil {
		return nil, fmt.Errorf("shit")
	}

	ctx := C.HMAC_CTX_new()
	if ctx == nil {
		return nil, fmt.Errorf("shit")
	}

	ret := &MACContext{ctx}
	runtime.SetFinalizer(ret, func(ret *MACContext) {
		C.HMAC_CTX_free(ret.hctx)
	})

	if 1 != C.HMAC_Init_ex(ctx, unsafe.Pointer(&key[0]), C.int(len(key)), md, nil) {
		return nil, fmt.Errorf("shit")
	}

	return ret, nil
}

func (ctx *MACContext) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if 1 != C.HMAC_Update(ctx.hctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) {
		return errors.New("hello")
	}
	return nil
}

func (ctx *MACContext) Final() ([]byte, error) {
	outbuf := make([]byte, 64)
	outlen := C.uint(len(outbuf))
	if 1 != C.HMAC_Final(ctx.hctx, (*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
		return nil, errors.New("error")
	}
	return outbuf[:outlen], nil
}
