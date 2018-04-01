/* +build cgo */
package gmssl

/*
#include <openssl/crypto.h>
*/
import "C"

func GetVersions() []string {
	versions := []string{
		"GmSSL Go API 1.1  Mar 31 2018",
		C.GoString(C.OpenSSL_version(C.OPENSSL_VERSION)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_BUILT_ON)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_CFLAGS)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_PLATFORM)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_DIR)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_ENGINES_DIR)),
	}
	return versions
}
