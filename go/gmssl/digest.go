/* +build cgo */

package gmssl

/*
#include <string.h>
#include <openssl/evp.h>
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

static void _OPENSSL_free(void *addr) {
	OPENSSL_free(addr);
}
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

type DigestContext struct {
	ctx *C.EVP_MD_CTX
}

func NewDigestContext(name string, eng *Engine) (*DigestContext, error) {
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

	if 1 != C.EVP_DigestInit(ctx, md) {
		return nil, GetErrors()
	}

	return ret, nil
}

func (ctx *DigestContext) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if 1 != C.EVP_DigestUpdate(ctx.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) {
		return GetErrors()
	}
	return nil
}

func (ctx *DigestContext) Final() ([]byte, error) {
	outbuf := make([]byte, 64)
	outlen := C.uint(len(outbuf))
	if 1 != C.EVP_DigestFinal(ctx.ctx, (*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
		return nil, GetErrors()
	}
	return outbuf[:outlen], nil
}
