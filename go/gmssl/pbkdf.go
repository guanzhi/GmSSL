/* +build cgo */
package gmssl

/*
#include <openssl/evp.h>
*/
import "C"

import (
	"errors"
)

func GetKeyDeriveFunctions(aliases bool) []string {
	return []string{"PBKDF2v1", "PBKDFv2", "scrypt"}
}

func DeriveKeyFromPassword(scheme string, args map[string]string, password string, salt []byte) ([]byte, error) {
	return nil, errors.New("Not implemented")
}


