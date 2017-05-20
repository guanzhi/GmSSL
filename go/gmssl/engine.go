/* +build cgo */
package gmssl

/*
#include <openssl/engine.h>
*/
import "C"

import (
	"runtime"
	"errors"
	"unsafe"
	"fmt"
)

func GetEngineNames() []string {
	return []string{"skf", "sdf"}
}

type Engine struct {
	engine *C.ENGINE
}

func OpenEngine(name string, args map[string]string) (*Engine, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	engine := C.ENGINE_by_id(cname)
	if engine == nil {
		return nil, fmt.Errorf("shit")
	}

	ret := &Engine{engine}
	runtime.SetFinalizer(ret, func(ret *Engine) {
		C.ENGINE_free(ret.engine)
	})
	return ret, nil
}

func (eng *Engine) ExecuteCommand(cmd_name string, arg string, optinal bool) error {
	ccmd := C.CString(cmd_name)
	defer C.free(unsafe.Pointer(ccmd))
	carg := C.CString(arg)
	defer C.free(unsafe.Pointer(carg))

	if 1 != C.ENGINE_ctrl_cmd_string(eng.engine, ccmd, carg, 0) {
		return errors.New("Not implemented")
	}
	return nil
}

func (eng *Engine) LoadPrivateKey(key_id string, args map[string]string) (*PrivateKey, error) {
	cid := C.CString(key_id)
	defer C.free(unsafe.Pointer(cid))

	pkey := C.ENGINE_load_private_key(eng.engine, cid, C.NULL, C.NULL)
	if pkey == nil {
		return nil, fmt.Errorf("shit")
	}

	ret := &PrivateKey{pkey}
	runtime.SetFinalizer(ret, func(ret *PrivateKey) {
		C.EVP_PKEY_free(ret.pkey)
	})
	return ret, nil
}

func (eng *Engine) LoadPublicKey(key_id string, args map[string]string) (*PublicKey, error) {
	cid := C.CString(key_id)
	defer C.free(unsafe.Pointer(cid))

	pkey := C.ENGINE_load_public_key(eng.engine, cid, C.NULL, C.NULL)
	if pkey == nil {
		return nil, fmt.Errorf("shit")
	}

	ret := &PublicKey{pkey}
	runtime.SetFinalizer(ret, func(ret *PublicKey) {
		C.EVP_PKEY_free(ret.pkey)
	})
	return ret, nil
}

func (eng *Engine) LoadCertificate(ca_dn []string, args map[string]string) (string, error) {
	return "", errors.New("Not implemented")
}
