package main

import (
	"gmssl"
	"gmssl/sm3"
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

	/* sm3 digest */
	sm3ctx, err := gmssl.NewDigestContext("SM3", nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := sm3ctx.Update([]byte("a")); err != nil {
		fmt.Println(err)
		return
	}
	if err := sm3ctx.Update([]byte("bc")); err != nil {
		fmt.Println(err)
		return
	}
	sm3digest, err := sm3ctx.Final()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("sm3(\"abc\") = %x\n", sm3digest)

	sm3hash := sm3.New()
	sm3hash.Write([]byte("abc"))
	fmt.Printf("sm3(\"abc\") = %x\n", sm3hash.Sum(nil))

	/* hmac-sm3 */
	hmac_sm3, err := gmssl.NewHMACContext("SM3", nil, []byte("this is the key"))
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := hmac_sm3.Update([]byte("ab")); err != nil {
		fmt.Println(err)
		return
	}
	if err := hmac_sm3.Update([]byte("c")); err != nil {
		fmt.Println(err)
		return
	}
	mactag, err := hmac_sm3.Final()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("hmac-sm3(\"abc\") = %x\n", mactag)

	/* generate random key */
	keylen, err := gmssl.GetCipherKeyLength("SMS4")
	if err != nil {
		fmt.Println(err)
		return
	}
	key, err := gmssl.GenerateRandom(keylen)
	if err != nil {
		fmt.Println(err)
		return
	}

	/* generate random iv */
	ivlen, err := gmssl.GetCipherIVLength("SMS4")
	if err != nil {
		fmt.Println(err)
		return
	}
	iv, err := gmssl.GenerateRandom(ivlen)
	if err != nil {
		fmt.Println(err)
		return
	}

	/* encrypt */
	encryptor, err := gmssl.NewCipherContext("SMS4", nil, key, iv, true)
	if err != nil {
		fmt.Println(err)
		return
	}
	ciphertext1, err := encryptor.Update([]byte("hello"))
	if err != nil {
		fmt.Println(err)
		return
	}
	ciphertext2, err := encryptor.Final()
	if err != nil {
		fmt.Println(err)
		return
	}
	ciphertext := make([]byte, 0, len(ciphertext1) + len(ciphertext2))
	ciphertext = append(ciphertext, ciphertext1...)
	ciphertext = append(ciphertext, ciphertext2...)

	/* decrypt */
	decryptor, err := gmssl.NewCipherContext("SMS4", nil, key, iv, false)
	if err != nil {
		fmt.Println(err)
		return
	}
	plaintext1, err := decryptor.Update(ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}
	plaintext2, err := decryptor.Final()
	if err != nil {
		fmt.Println(err)
		return
	}
	plaintext := make([]byte, 0, len(plaintext1) + len(plaintext2))
	plaintext = append(plaintext, plaintext1...)
	plaintext = append(plaintext, plaintext2...)

	fmt.Printf("sms4(\"%s\") = %x\n", plaintext, ciphertext)

}

