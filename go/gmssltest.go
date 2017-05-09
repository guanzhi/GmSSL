package main

import (
	"gmssl"
	"fmt"
)

func main() {

	versions := gmssl.GetVersion()
	for _, version := range versions {
		fmt.Println(version)
	}

	digests := gmssl.GetDigests(false)
	for _, digest := range digests {
		fmt.Println(digest)
	}

	ciphers := gmssl.GetCiphers(false)
	for _, cipher := range ciphers {
		fmt.Println(cipher)
	}

	macs := gmssl.GetMacs(false)
	for _, mac := range macs {
		fmt.Println(mac)
	}

	sm3, err := gmssl.NewDigestContext("SM3", nil)
	if err != nil {
	}

	if err := sm3.Update([]byte("hello")); err != nil {
	}

	if err := sm3.Update([]byte("world")); err != nil {
	}

	sm3digest, err := sm3.Final()
	if err != nil {
	}
	fmt.Printf("%x", sm3digest)


	hmac_sm3, err := gmssl.NewMACContext("HMAC-SM3", nil, []byte("this is the key"))
	if err != nil {
	}

	if err := hmac_sm3.Update([]byte("hello")); err != nil {
	}

	if err := hmac_sm3.Update([]byte("world")); err != nil {
	}

	mactag, err := hmac_sm3.Final()
	if err != nil {
	}
	fmt.Printf("%x", mactag)

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

}

