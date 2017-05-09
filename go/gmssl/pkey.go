/* +build cgo */
package gmssl

/*
#include <openssl/evp.h>
*/
import "C"

import (
	"errors"
)

func GetPublicKeyTypes(aliases bool) []string {
	return []string{"RSA", "DH", "DSA"}
}

func GetSignatureSchemes(publicKeyType string, aliases bool) []string {
	return []string{"RSA", "DSA", "ECDSA", "SM2"}
}

func GetPublicKeyEncryptions(publicKeyType string, aliases bool) []string {
	return []string{"RSA", "ECIES", "SM2"}
}

func GetKeyExchanges(publicKeyType string, aliases bool) []string {
	return []string{"DH", "ECDH", "SM2"}
}

type PublicKey struct {
	pkey *C.EVP_PKEY
}

type PrivateKey struct {
	pkey *C.EVP_PKEY
}

func GenerateKeyPair(publicKeyType string, args map[string]string, bits int) (*PublicKey, *PrivateKey, error) {
	return nil, nil, errors.New("Not implemented")
}

func LoadPublicKey(publicKeyType string, args map[string]string, data []byte) (*PublicKey, error) {
	return nil, errors.New("Not implemented")
}

func LoadPrivateKey(publicKeyType string, args map[string]string, data []byte) (*PrivateKey, error) {
	return nil, errors.New("Not implemented")
}

func (pkey *PublicKey) Save(args map[string]string) ([]byte, error) {
	return nil, errors.New("Not implemented")
}

func (pkey *PrivateKey) Save(args map[string]string) ([]byte, error) {
	return nil, errors.New("Not implemented")
}

func (pkey *PublicKey) GetAttributes(args map[string]string) (map[string]string, error) {
	return nil, errors.New("Not implemented")
}

func (pkey *PrivateKey) GetAttributes(args map[string]string) (map[string]string, error) {
	return nil, errors.New("Not implemented")
}

func (pkey *PublicKey) Encrypt(scheme string, args map[string]string, in []byte) ([]byte, error) {
	ctx := C.EVP_PKEY_CTX_new(pkey.pkey, nil)
	if ctx == nil {
		return nil, errors.New("Failure")
	}
	if 1 != C.EVP_PKEY_encrypt_init(ctx) {
		return nil, errors.New("Failurew")
	}
	outbuf := make([]byte, len(in) + 1024)
	outlen := C.size_t(len(outbuf))
	if 1 != C.EVP_PKEY_encrypt(ctx, (*C.uchar)(&outbuf[0]), &outlen,
		(*C.uchar)(&in[0]), C.size_t(len(in))) {
		return nil, errors.New("Failurew")
	}
	return outbuf[:outlen], nil
}

func (pkey *PrivateKey) Decrypt(scheme string, args map[string]string, in []byte) ([]byte, error) {
	ctx := C.EVP_PKEY_CTX_new(pkey.pkey, nil)
	if ctx == nil {
		return nil, errors.New("Failure")
	}
	if 1 != C.EVP_PKEY_decrypt_init(ctx) {
		return nil, errors.New("Failure")
	}
	outbuf := make([]byte, len(in))
	outlen := C.size_t(len(outbuf))
	if 1 != C.EVP_PKEY_decrypt(ctx, (*C.uchar)(&outbuf[0]), &outlen,
		(*C.uchar)(&in[0]), C.size_t(len(in))) {
		return nil, errors.New("Failure")
	}
	return outbuf[:outlen], nil
}

func (pkey *PrivateKey) Sign(scheme string, args map[string]string, data []byte) ([]byte, error) {
	ctx := C.EVP_PKEY_CTX_new(pkey.pkey, nil)
	if ctx == nil {
		return nil, errors.New("Failure")
	}
	if 1 != C.EVP_PKEY_sign_init(ctx) {
		return nil, errors.New("Failure")
	}
	outbuf := make([]byte, C.EVP_PKEY_size(pkey.pkey))
	outlen := C.size_t(len(outbuf))
	if 1 != C.EVP_PKEY_sign(ctx, (*C.uchar)(&outbuf[0]), &outlen,
		(*C.uchar)(&data[0]), C.size_t(len(data))) {
		return nil, errors.New("Failure")
	}
	return outbuf[:outlen], nil
}

func (pkey *PublicKey) Verify(scheme string, args map[string]string, data, signature []byte) error {
	ctx := C.EVP_PKEY_CTX_new(pkey.pkey, nil)
	if ctx == nil {
		return errors.New("Failure")
	}
	if 1 != C.EVP_PKEY_sign_init(ctx) {
		return errors.New("Failure")
	}
	ret := C.EVP_PKEY_verify(ctx, (*C.uchar)(&signature[0]), C.size_t(len(signature)),
		(*C.uchar)(&data[0]), C.size_t(len(data)))
	if ret != 1 {
		return errors.New("Failure")
	}
	return nil
}

func (pkey *PrivateKey) DeriveKey(scheme string, args map[string]string, publicKey PublicKey) ([]byte, error) {
	ctx := C.EVP_PKEY_CTX_new(pkey.pkey, nil)
	if ctx == nil {
		return nil, errors.New("Failure")
	}
	if 1 != C.EVP_PKEY_derive_init(ctx) {
	}
	/*
	if 1 != C.EVP_PKEY_derive_set_peer(ctx, PublicKey.pkey) {
	}
	*/

	outbuf := make([]byte, C.EVP_PKEY_size(pkey.pkey))
	outlen := C.size_t(len(outbuf))
	if 1 != C.EVP_PKEY_derive(ctx, (*C.uchar)(&outbuf[0]), &outlen) {
	}
	return nil, errors.New("Not implemented")
}
