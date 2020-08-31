package main

import (
	"github.com/Hyperledger-TWGC/pku-gm/gmssl"
	"testing"
)

func TestSM2KeyPemExport(t *testing.T) {
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
	WriteFile([]byte(pem), pemFile, t)

}
func TestSM2KeyPemImport(t *testing.T) {
	var pemFile = "privateKey.pem"
	var pemBytes = ReadFile(pemFile, t)
	_, err := gmssl.NewPrivateKeyFromPEM(string(pemBytes), "")
	PanicError(err)
}
