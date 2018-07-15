package main

import (
	"gmssl"
	"fmt"
)

func main() {

	versions := gmssl.GetVersions()
	fmt.Println("GmSSL Versions:")
	for _, version := range versions {
		fmt.Println("    " + version)
	}
	fmt.Println("");

	fmt.Println("Supported Digest Algorithms:")
	digests := gmssl.GetDigestNames()
	for _, digest := range digests {
		fmt.Println("    " + digest)
	}
	fmt.Println("");

	fmt.Println("Supported Ciphers:")
	ciphers := gmssl.GetCipherNames()
	for _, cipher := range ciphers {
		fmt.Println("    " + cipher)
	}
	fmt.Println("");

	fmt.Println("Supported Message Authentication Codes:")
	macs := gmssl.GetMacNames()
	for _, mac := range macs {
		fmt.Println("    " + mac)
	}
	fmt.Println("");

	sm3, err := gmssl.NewDigestContext("SM3", nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := sm3.Update([]byte("a")); err != nil {
		fmt.Println(err)
		return
	}
	if err := sm3.Update([]byte("bc")); err != nil {
		fmt.Println(err)
		return
	}
	sm3digest, err := sm3.Final()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("sm3(\"abc\") = %x\n", sm3digest)

	hmac_sm3, err := gmssl.NewHMACContext("SM3", nil, []byte("this is the key"))
	if err != nil {
		fmt.Println("shit1")
		return
	}
	if err := hmac_sm3.Update([]byte("hello")); err != nil {
		fmt.Println("shit2")
		return
	}
	if err := hmac_sm3.Update([]byte("world")); err != nil {
		fmt.Println("shit3")
		return
	}
	mactag, err := hmac_sm3.Final()
	if err != nil {
		fmt.Println("shit4")
		return
	}
	fmt.Printf("hmac-sm3() = %x\n", mactag)

	/*
	key := []byte("key")
	iv := []byte("iv")
	sms4, err := gmssl.NewCipherContext("SMS4", nil, key, iv, true)
	if err != nil {
	}

	ciphertext1, err := sms4.Update([]byte("hello"))
	if err != nil {
	}

	ciphertext2, err := sms4.Final()
	if err != nil {
	}

	ciphertext := make([]byte, 0, len(ciphertext1) + len(ciphertext2))
	ciphertext = append(ciphertext, ciphertext1...)
	ciphertext = append(ciphertext, ciphertext2...)
	fmt.Printf("%x", ciphertext)
	*/
}

