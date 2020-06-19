package gosm2

import (
	"testing"

	//"encoding/hex"
	"fmt"
)

var (
	str   = "just test sm2 sign/verify!!!"
	bytes = []byte(str)
)

func sm2run_hex() bool {
	priv, err := GenPrivateKey_hex()
	if err != nil {
		fmt.Println("priv err:", err)
		return false
	}
	// priv, _ := hex.DecodeString("EDE9E0C0EAA4BF0B9B0B9BF2643E1DD3C57FE16ABF2F33A92F07A2849E6812E3")
	// fmt.Printf("hexpriv = %x\n", priv)
	sig, err := SignData_hex(priv, str)
	if err != nil {
		fmt.Println("sig err:", err)
		return false
	}
	if len(sig) == 0 {
		return false
	}
	pub, err := GenPublicKeyByPriv_hex(priv)
	if err != nil {
		fmt.Println("pub err:", err)
		return false
	}
	ok, err := VerifyData_hex(pub, sig, str)
	if !ok {
		fmt.Println("VerifyData err:", err)
		return false
	}
	return true
}

func sm2run_bin() bool {
	priv, err := GenPrivateKey_bin()
	if err != nil {
		fmt.Println("priv err:", err)
		return false
	}
	// priv, _ := hex.DecodeString("EDE9E0C0EAA4BF0B9B0B9BF2643E1DD3C57FE16ABF2F33A92F07A2849E6812E3")
	// fmt.Printf("hexpriv = %x\n", priv)
	sig, err := SignData_bin(priv, bytes)
	if err != nil {
		fmt.Println("sig err:", err)
		return false
	}
	if len(sig) == 0 {
		return false
	}
	pub, err := GenPublicKeyByPriv_bin(priv)
	if err != nil {
		fmt.Println("pub err:", err)
		return false
	}
	ok, err := VerifyData_bin(pub, sig, bytes)
	if !ok {
		fmt.Println("VerifyData err:", err)
		return false
	}
	return true
}

func TestGMSSL(t *testing.T) {
	sm2run_hex()
	sm2run_bin()
}

func BenchmarkSM2_Hex(t *testing.B) {
	for i := 0; i < t.N; i++ {
		if !sm2run_hex() {
			break
		}
	}
}

func BenchmarkSM2_Binary(t *testing.B) {
	for i := 0; i < t.N; i++ {
		if !sm2run_bin() {
			break
		}
	}
}
