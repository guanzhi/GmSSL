/* +build cgo */
package gosm2

/*

#cgo CFLAGS: -std=c99 -I../../include -I../csm2
#cgo LDFLAGS: -L../libs -lcrypto -ldl -lpthread

#include "../csm2/sm2.err.c"
*/
import "C"

import (
	"errors"
)

const Buf_size = 4096

func CSM2Error() error {
	buf := make([]byte, Buf_size)
	errno := C.SM2Error(bytes2cbytes(buf), C.int(Buf_size))
	if errno == 0 {
		return nil
	}
	return errors.New(string(buf))
}
