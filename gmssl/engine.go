/*
 * Copyright (c) 2017 - 2018 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
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
	engine *C.ENGINE;
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
	if 1 != C.ENGINE_init(eng) {
		return nil, GetErrors()
	}
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
