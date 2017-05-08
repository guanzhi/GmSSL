/* +build cgo */
package gmssl

/*
#include <openssl/x509.h>
#include <openssl/pem.h>
*/
import "C"

import (
	"errors"
)

func GetAttributesFromCertificate(cert string) (map[string]string, error) {
	return nil, errors.New("Not implemented")
}

func GetPublicKeyFromCertificate(cert string) (*PublicKey, error) {
	return nil, errors.New("Not implemented")
}
