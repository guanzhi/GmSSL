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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ui.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

func GetEngineNames() []string {
	engines := []string{}
	C.ENGINE_load_builtin_engines()
	eng := C.ENGINE_get_first()
	for {
		if eng == nil {
			break
		}
		engines = append(engines, C.GoString(C.ENGINE_get_id(eng)))
		eng = C.ENGINE_get_next(eng)
	}
	C.ENGINE_free(eng)
	return engines
}

type Engine struct {
	engine *C.ENGINE
}

func NewEngineByName(name string) (*Engine, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	eng := C.ENGINE_by_id(cname)
	if eng == nil {
		return nil, GetErrors()
	}
	ret := &Engine{eng}
	runtime.SetFinalizer(ret, func(ret *Engine) {
		C.ENGINE_finish(ret.engine)
	})
	/*
		Engine is not configured by default
		So this check will fail in test
		We disable this check now.
		if 1 != C.ENGINE_init(eng) {
			return nil, GetErrors()
		}*/
	return ret, nil
}

func (e *Engine) GetCommands() ([]string, error) {
	return []string{"SO_PATH"}, nil
}

func (e *Engine) RunCommand(name, arg string) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	carg := C.CString(arg)
	defer C.free(unsafe.Pointer(carg))
	if 1 != C.ENGINE_ctrl_cmd_string(e.engine, cname, carg, 0) {
		return GetErrors()
	}
	return nil
}

func (e *Engine) LoadConfigFile(path string) error {
	return errors.New("Engine.LoadConfigFile() not implemented")
}

func (e *Engine) GetPrivateKey(id string, pass string) (*PrivateKey, error) {
	cid := C.CString(id)
	defer C.free(unsafe.Pointer(cid))
	cpass := C.CString(pass)
	defer C.free(unsafe.Pointer(cpass))
	sk := C.ENGINE_load_private_key(e.engine, cid, nil,
		unsafe.Pointer(cpass))
	if sk == nil {
		return nil, GetErrors()
	}
	return &PrivateKey{sk}, nil
}

func (e *Engine) GetPublicKey(id string, pass string) (*PublicKey, error) {
	cid := C.CString(id)
	defer C.free(unsafe.Pointer(cid))
	cpass := C.CString(pass)
	defer C.free(unsafe.Pointer(cpass))

	pk := C.ENGINE_load_public_key(e.engine, cid, nil,
		unsafe.Pointer(cpass))
	if pk == nil {
		return nil, GetErrors()
	}
	return &PublicKey{pk}, nil
}
