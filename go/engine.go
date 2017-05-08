/* +build cgo */
package gmssl

/*
#include <openssl/engine.h>
*/
import "C"

import (
	"errors"
)

func GetEngineNames() []string {
	return []string{"skf", "sdf"}
}

type Engine struct {
	engine *C.ENGINE
}

func OpenEngine(name string, args map[string]string) (*Engine, error) {
	return nil, errors.New("Not implemented")
}

func (eng *Engine) ExecuteCommand(cmd_name string, arg string, optinal bool) (string, error) {
	return "", errors.New("Not implemented")
}

func (eng *Engine) LoadPrivateKey(key_id string, args map[string]string) (*PrivateKey, error) {
	return nil, errors.New("Not implemented")
}

func (eng *Engine) LoadPublicKey(key_id string, args map[string]string) (*PublicKey, error) {
	return nil, errors.New("Not implemented")
}

func (eng *Engine) LoadCertificate(ca_dn []string, args map[string]string) (string, error) {
	return "", errors.New("Not implemented")
}
