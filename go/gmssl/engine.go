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

char *get_errors() {
	char *ret;
	BIO *bio;
	char *data;
	long len;
	if (!(bio = BIO_new(BIO_s_mem()))) {
		return (char *)NULL;
	}
	ERR_print_errors(bio);
	len = BIO_get_mem_data(bio, &data);
	ret = OPENSSL_strdup(data);
	BIO_free(bio);
	return ret;
}

EVP_PKEY *load_public_key(ENGINE *e, const char *id, char *pass) {
	return ENGINE_load_public_key(e, id, NULL, pass);
}

EVP_PKEY *load_private_key(ENGINE *e, const char *id, char *pass) {
	return ENGINE_load_private_key(e, id, NULL, pass);
}

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

func GetEngineByName(name string) (*Engine, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	eng := C.ENGINE_by_id(cname)
	if eng == nil {
		cerrors := C.get_errors()
		return nil, errors.New(C.GoString(cerrors))
	}
	ret := &Engine{eng}
	runtime.SetFinalizer(ret, func(ret *Engine) {
		C.ENGINE_finish(ret.engine)
		C.ENGINE_free(ret.engine)
	})
	if 1 != C.ENGINE_init(eng) {
		cerrors := C.get_errors()
		return nil, errors.New(C.GoString(cerrors))
	}
	return ret, nil
}

func (e *Engine) RunCommand(name, arg string) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	carg := C.CString(arg)
	defer C.free(unsafe.Pointer(carg))
	if 1 != C.ENGINE_ctrl_cmd_string(e.engine, cname, carg, 0) {
		cerrors := C.get_errors()
		return errors.New(C.GoString(cerrors))
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
	sk := C.load_private_key(e.engine, cid, cpass)
	if sk == nil {
		cerrors := C.get_errors()
		return nil, errors.New(C.GoString(cerrors))
	}
	return &PrivateKey{sk}, nil
}

func (e *Engine) GetPublicKey(id string, pass string) (*PublicKey, error) {
	cid := C.CString(id)
	defer C.free(unsafe.Pointer(cid))
	cpass := C.CString(pass)
	defer C.free(unsafe.Pointer(cpass))
	pk := C.load_public_key(e.engine, cid, cpass)
	if pk == nil {
		cerrors := C.get_errors()
		return nil, errors.New(C.GoString(cerrors))
	}
	return &PublicKey{pk}, nil
}
