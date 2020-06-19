/* +build cgo */
package gosm2

/*
#include "../csm2/sm2.hex.c"
*/
import "C"

import (
	"encoding/hex"
	"fmt"
	"unsafe"
)

func GenPrivateKey_hex() ([]byte, error) {
	key := C.GeneratePrivateKey_hex()
	if key == nil {
		return nil, CSM2Error()
	}
	gokey := C.GoString(key)
	C.SM2Free(key)
	return hex.DecodeString(gokey)
}

func GenPublicKeyByPriv_hex(pri []byte) ([]byte, error) {
	hexstr := C.CString(fmt.Sprintf("%x", pri))
	pub := C.GetPublicKeyByPriv_hex(hexstr)
	C.free(unsafe.Pointer(hexstr))
	if pub == nil {
		return nil, CSM2Error()
	}
	gokey := C.GoString(pub)
	C.SM2Free(pub)
	return hex.DecodeString(gokey)
}

func SignData_hex(priv []byte, data string) ([]byte, error) {
	hexstr := C.CString(fmt.Sprintf("%x", priv))
	hexmsg := C.CString(data)

	sdata := C.Sign_hex(hexstr, hexmsg, C.int(len(data)))

	C.free(unsafe.Pointer(hexstr))
	C.free(unsafe.Pointer(hexmsg))
	//
	if sdata == nil {
		return nil, CSM2Error()
	}
	gokey := C.GoString(sdata)
	C.SM2Free(sdata)

	if len(gokey) == 0 {
		return []byte{}, nil
	}
	return hex.DecodeString(gokey)
}

func VerifyData_hex(pub, sig []byte, msg string) (bool, error) {
	hexstr := C.CString(fmt.Sprintf("%x", pub))
	hexsig := C.CString(fmt.Sprintf("%x", sig))
	hexmsg := C.CString(msg)

	ret := C.Verify_hex(hexstr, hexsig, hexmsg, C.int(len(msg)))

	C.free(unsafe.Pointer(hexstr))
	C.free(unsafe.Pointer(hexsig))
	C.free(unsafe.Pointer(hexmsg))
	//
	if ret == 1 {
		return true, nil
	}
	return false, CSM2Error()
}
