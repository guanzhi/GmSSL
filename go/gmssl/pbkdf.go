/* +build cgo */
package gmssl

/*
#include <openssl/evp.h>
*/
import "C"

import (
	"errors"
)

/*
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                      const unsigned char *salt, int saltlen, int iter,
                      const EVP_MD *digest, int keylen, unsigned char *out);
int EVP_PBE_scrypt(const char *pass, size_t passlen,
                   const unsigned char *salt, size_t saltlen,
                   uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
                   unsigned char *key, size_t keylen);
*/

func GetKeyDeriveFunctions(aliases bool) []string {
	return []string{"PBKDF", "PBKDF2", "scrypt"}
}

func DeriveKeyFromPassword(algor string, args map[string]string, password string, salt []byte, keylen int) ([]byte, error) {
	if algor == "PBKDF2" {
		if 1 != PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, md, keylen, out) {
		}
	else if algor == "scrypt" {
		if 1 != gmssl_scrypt()
	} else {
		return nil, errors.New("Not implemented")
	}
}
