/* +build cgo */
package gosm2

/*
#include "../csm2/sm2.bin.c"
*/
import "C"

import (
	"unsafe"
)

func bytes2cbytes(b []byte) *C.uchar {
	p := &b[0]
	return (*C.uchar)(p)
}

func GenPrivateKey_bin() ([]byte, error) {
	key := C.GeneratePrivateKey_bin()
	if key == nil {
		return nil, CSM2Error()
	}
	gokey := C.GoBytes(unsafe.Pointer(key), C.Size_PriKey)
	C.SM2Free(key)
	return gokey, nil
}

func GenPublicKeyByPriv_bin(priv []byte) ([]byte, error) {
	pub := C.GetPublicKeyByPriv_bin(bytes2cbytes(priv), C.int(len(priv)))
	if pub == nil {
		return nil, CSM2Error()
	}
	gokey := C.GoBytes(unsafe.Pointer(pub), C.Size_PubKey)
	C.SM2Free(pub)
	return gokey, nil
}

func SignData_bin(priv []byte, data []byte) ([]byte, error) {
	sdata := C.Sign_bin(bytes2cbytes(priv), C.int(len(priv)), bytes2cbytes(data), C.int(len(data)))
	if sdata == nil {
		return nil, CSM2Error()
	}
	gokey := C.GoBytes(unsafe.Pointer(sdata), C.Size_Signure)
	C.SM2Free(sdata)
	return gokey, nil
}

func VerifyData_bin(pub, sig []byte, msg []byte) (bool, error) {
	ret := C.Verify_bin(bytes2cbytes(pub), bytes2cbytes(sig), bytes2cbytes(msg), C.int(len(msg)))
	if ret == 1 {
		return true, nil
	}
	return false, CSM2Error()
}
