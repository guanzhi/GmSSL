package main

import (
	"github.com/Hyperledger-TWGC/pku-gm/gmssl"
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
	_, err = sm2sk.GetPEM("", "") // TODO no encrypt mode is not supported.
	PanicError(err)
}
