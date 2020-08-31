package main

import (
	"github.com/Hyperledger-TWGC/pku-gm/gmssl"
	"os"
	"testing"
)

func TestSM2KeyPemNoEncrypt(t *testing.T) {
	/* SM2 key pair operations */
	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := gmssl.GeneratePrivateKey("EC", sm2keygenargs, nil)
	PanicError(err)
	pem, err := sm2sk.GetPEM("", "") // no encrypt mode is supported by not encouraged to use with security concern
	PanicError(err)
	var pemFile = "privateKey.pem"
	file, err := os.Create(pemFile)
	PanicError(err)
	defer func() {
		err = file.Close()
		PanicError(err)
	}()
	_, err = file.Write([]byte(pem))
	PanicError(err)

}
