/* +build cgo */
package gmssl

/*
#include <openssl/rand.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

func SeedRandom(seed []byte) error {
	C.RAND_seed(unsafe.Pointer(&seed[0]), C.int(len(seed)))
	return nil
}

func GenerateRandom(length int) ([]byte, error) {
	outbuf := make([]byte, length)
	if 1 != C.RAND_bytes((*C.uchar)(&outbuf[0]), C.int(length)) {
		return nil, errors.New("GmSSL Failure")
	}

	return outbuf[:length], nil
}
