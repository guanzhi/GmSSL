/* +build cgo */

package gmssl

/*
#cgo darwin CFLAGS: -I/usr/local/include
#cgo darwin LDFLAGS: -L/usr/local/lib -lcrypto

#include <openssl/bio.h>
#include <openssl/crypto.h>

long _BIO_get_mem_data(BIO *b, char **pp) {
	return BIO_get_mem_data(b, pp);
}

void _OPENSSL_free(void *addr) {
	OPENSSL_free(addr);
}
*/
import "C"
