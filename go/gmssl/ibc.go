/* +build cgo */
package gmssl

/*
#include <openssl/rand.h>
#include <openssl/evp.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

func GetIdentityBasedCryptoSchemes(aliases bool) []string {
	return []string{"CPK", "SM9", "BFIBE", "BB1IBE"}
}

type MasterSecret struct {
	pkey *C.EVP_PKEY
}

type PublicParams struct {
	pkey *C.EVP_PKEY
}

func IdentityBasedCryptoSetup() {
}

func IdentityBasedCryptoExportPrivateKey() {
}

func IdentityBasedCryptoExportPublicKey() {
}

func IdentityBasedEncrypt() {
}

func IdentityBasedDecrypt() {
}

func IdentityBasedSign() {
}

func IdentityBasedVerify() {
}

func GetCipherKeyLength(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	cipher := C.EVP_get_cipherbyname(cname)
	if cipher == nil {
		return 0, errors.New("Invalid cipher name")



