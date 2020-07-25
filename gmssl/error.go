/*
 * Copyright 2020 The Hyperledger-TWGC Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* +build cgo */
package gmssl

/*
#include <openssl/err.h>
#include <openssl/bio.h>


extern long _BIO_get_mem_data(BIO *b, char **pp);
*/
import "C"

import (
	"errors"
)

func PanicError(err error) {
	if err != nil {
		panic(err)
	}
}
func GetErrors() error {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return errors.New("GetErrors function failure 1")
	}
	defer C.BIO_free(bio)
	C.ERR_print_errors(bio)
	var p *C.char
	l := C._BIO_get_mem_data(bio, &p)
	if l <= 0 {
		return errors.New("GetErrors function failure 2")
	}
	return errors.New(C.GoString(p))
}
