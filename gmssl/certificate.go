/*
 * Copyright 1995-2020 The Hyperledger-TWGC Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* +build cgo */
package gmssl

/*
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/objects.h>
#include <openssl/opensslconf.h>

extern long _BIO_get_mem_data(BIO *b, char **pp);
extern void _OPENSSL_free(void *addr);
*/
import "C"

import (
	"fmt"
	"unsafe"
	"runtime"
)

type Certificate struct {
	x509 *C.X509
}

func NewCertificateFromPEM(pem string, pass string) (*Certificate, error) {
	cpem := C.CString(pem)
	defer C.free(unsafe.Pointer(cpem))
	cpass := C.CString(pass)
	defer C.free(unsafe.Pointer(cpass))

	bio := C.BIO_new_mem_buf(unsafe.Pointer(cpem), -1)
	if bio == nil {
		return nil, GetErrors()
	}
	defer C.BIO_free(bio)

	x509 := C.PEM_read_bio_X509(bio, nil, nil, unsafe.Pointer(cpass))
	if x509 == nil {
		return nil, GetErrors()
	}
	ret := &Certificate{x509}
	runtime.SetFinalizer(ret, func(ret *Certificate) {
		C.X509_free(ret.x509)
	})

	return ret, nil
}

func (cert *Certificate) GetSubject() (string, error) {
	name := C.X509_get_subject_name(cert.x509)
	if name == nil {
		return "", GetErrors()
	}
	str := C.X509_NAME_oneline(name, nil, 0)
	if str == nil {
		return "", GetErrors()
	}
	defer C._OPENSSL_free(unsafe.Pointer(str))
	return C.GoString(str), nil
}

func (cert *Certificate) GetIssuer() (string, error) {
	name := C.X509_get_issuer_name(cert.x509)
	if name == nil {
		return "", GetErrors()
	}
	str := C.X509_NAME_oneline(name, nil, 0)
	if str == nil {
		return "", GetErrors()
	}
	defer C._OPENSSL_free(unsafe.Pointer(str))
	return C.GoString(str), nil
}

func (cert *Certificate) GetSerialNumber() (string, error) {
	serial := C.X509_get0_serialNumber(cert.x509)
	if serial == nil {
		return "", GetErrors()
	}
	bn := C.ASN1_INTEGER_to_BN(serial, nil)
	if bn == nil {
		return "", GetErrors()
	}
	defer C.BN_free(bn)
	hex := C.BN_bn2hex(bn)
	if hex == nil {
		return "", GetErrors()
	}
	defer C._OPENSSL_free(unsafe.Pointer(hex))
	return C.GoString(hex), nil
}

func (cert *Certificate) GetPublicKey() (*PublicKey, error) {
	pkey := C.X509_get_pubkey(cert.x509)
	if pkey == nil {
		return nil, GetErrors()
	}
	ret := &PublicKey{pkey}
	runtime.SetFinalizer(ret, func(ret *PublicKey) {
		C.EVP_PKEY_free(ret.pkey)
	})
	return ret, nil
}

func (cert *Certificate) GetText() (string, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return "", GetErrors()
	}
	defer C.BIO_free(bio)
	if 0 >= C.X509_print(bio, cert.x509) {
		return "", GetErrors()
	}
	var p *C.char
	len := C._BIO_get_mem_data(bio, &p)
	if len <= 0 {
		return "", GetErrors()
	}
	return C.GoString(p)[:len], nil
}

func (cert *Certificate) CheckPrivateKey(skey *PrivateKey) error {
	if 1 != C.X509_check_private_key(cert.x509, skey.pkey) {
		err := GetErrors()
		if err == nil {
			return fmt.Errorf("failure")
		}
		return err
	}
	return nil
}
