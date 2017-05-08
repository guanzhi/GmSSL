/* +build cgo */
package gmssl

/*
#include <openssl/crypto.h>
*/
import "C"

func GetVersion() []string {
	version := []string{
		C.GoString(C.OpenSSL_version(C.OPENSSL_VERSION)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_BUILT_ON)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_CFLAGS)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_PLATFORM)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_DIR)),
		C.GoString(C.OpenSSL_version(C.OPENSSL_ENGINES_DIR)),
	}
	return version
}
