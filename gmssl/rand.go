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
#include <openssl/rand.h>
*/
import "C"

import (
	"unsafe"
)

func SeedRandom(seed []byte) error {
	C.RAND_seed(unsafe.Pointer(&seed[0]), C.int(len(seed)))
	return nil
}

func GenerateRandom(length int) ([]byte, error) {
	outbuf := make([]byte, length)
	if C.RAND_bytes((*C.uchar)(&outbuf[0]), C.int(length)) <= 0 {
		return nil, GetErrors()
	}
	return outbuf[:length], nil
}
