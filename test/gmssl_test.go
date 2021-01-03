/*
 * Copyright 2020 The Hyperledger-TWGC Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/Hyperledger-TWGC/pku-gm/gmssl"
)

func newSM3DigestContext() *gmssl.DigestContext {
	sm3ctx, err := gmssl.NewDigestContext(gmssl.SM3)
	PanicError(err)
	return sm3ctx
}
func TestDigest(t *testing.T) {
	/* SM3 digest with GmSSL-Go API */
	sm3ctx := newSM3DigestContext()
	s1 := []byte("a")
	s2 := []byte("bc")
	err := sm3ctx.Update(s1)
	PanicError(err)
	err = sm3ctx.Update(s2)
	PanicError(err)
	sm3digest, err := sm3ctx.Final()
	PanicError(err)
	fmt.Printf("sm3(%s) = %x\n", append(s1[:], s2[:]...), sm3digest)
}
func TestDigestHash(t *testing.T) {
	/* SM3 digest with Go hash.Hash API */
	sm3hash := gmssl.New()
	s1 := []byte("abc")
	sm3hash.Write(s1)
	fmt.Printf("sm3(%s) = %x\n", s1, sm3hash.Sum(nil))
}
func TestHMAC(t *testing.T) {
	/* HMAC-SM3 */
	hmacSm3, err := gmssl.NewHMACContext(gmssl.SM3, []byte("this is the key"))
	PanicError(err)
	s1 := []byte("ab")
	s2 := []byte("c")
	err = hmacSm3.Update(s1)
	err = hmacSm3.Update(s2)
	PanicError(err)
	macTag, err := hmacSm3.Final()
	PanicError(err)
	fmt.Printf("hmac-sm3(%s) = %x\n", append(s1[:], s2[:]...), macTag)
}
func randomKey() []byte {
	keyLen, err := gmssl.GetCipherKeyLength(gmssl.SMS4)
	PanicError(err)
	key, err := gmssl.GenerateRandom(keyLen)
	PanicError(err)
	return key
}
func randomIV() []byte {
	ivlen, err := gmssl.GetCipherIVLength(gmssl.SMS4)
	PanicError(err)
	iv, err := gmssl.GenerateRandom(ivlen)
	PanicError(err)
	return iv
}

// SMS4-CBC Encrypt/Decrypt
func TestSMS4CBC(t *testing.T) {
	/* Generate random key and IV */
	key := randomKey()
	iv := randomIV()
	rawContent := []byte("hello")
	encrypt, err := gmssl.NewCipherContext(gmssl.SMS4, key, iv, true)
	PanicError(err)
	ciphertext1, err := encrypt.Update(rawContent)
	PanicError(err)
	ciphertext2, err := encrypt.Final()
	PanicError(err)
	ciphertext := make([]byte, 0, len(ciphertext1)+len(ciphertext2))
	ciphertext = append(ciphertext, ciphertext1...)
	ciphertext = append(ciphertext, ciphertext2...)

	decryptor, err := gmssl.NewCipherContext(gmssl.SMS4, key, iv, false)
	PanicError(err)
	plaintext1, err := decryptor.Update(ciphertext)
	PanicError(err)
	plaintext2, err := decryptor.Final()
	PanicError(err)
	plaintext := make([]byte, 0, len(plaintext1)+len(plaintext2))
	plaintext = append(plaintext, plaintext1...)
	plaintext = append(plaintext, plaintext2...)

	if string(plaintext) != string(rawContent) {
		t.Fatalf("decrypt result should be %s, but got %s", rawContent, plaintext)
	}

	fmt.Printf("sms4_cbc(%s) = %x\n", plaintext, ciphertext)
}

func TestSMS4ECB(t *testing.T) {

	key := randomKey()
	rawContent := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	ciphertext, err := gmssl.CipherECBenc(rawContent, key)

	PanicError(err)
	fmt.Printf("ciphertext = %x\n", ciphertext)
	plaintext, err := gmssl.CipherECBdec(ciphertext, key)

	PanicError(err)

	fmt.Printf("plaintext = %x\n", plaintext)

	if string(plaintext) != string(rawContent) {

		t.Fatalf("decrypt result should be %x, but got %x", rawContent, plaintext)
	}

	fmt.Printf("sms4_ecb(%x) = %x\n", plaintext, rawContent)
}

func TestRSA(t *testing.T) {
	/* private key */
	rsaArgs := [][2]string{
		{"rsa_keygen_bits", "2048"},
		{"rsa_keygen_pubexp", "65537"},
	}

	rsa, err := gmssl.GeneratePrivateKey("RSA", rsaArgs, nil)
	PanicError(err)
	rsaPem, err := rsa.GetPublicKeyPEM()
	PanicError(err)
	fmt.Println(rsaPem)
}
func TestEngineCommands(t *testing.T) {
	engines := gmssl.GetEngineNames()

	for _, engine := range engines {
		eng, err := gmssl.NewEngineByName(engine)
		fmt.Printf("\n testing on engine=[%s] \n", engine)
		// FIXME: it fails when engine==dynamic
		PanicError(err)
		cmds, err := eng.GetCommands()
		PanicError(err)
		for _, cmd := range cmds {
			fmt.Printf("engine[%s].cmd[%s] \n", engine, cmd)
		}
	}

}

var sm2pkpem string // global variable
func TestKeyPair(t *testing.T) {
	/* SM2 key pair operations */
	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := gmssl.GeneratePrivateKey("EC", sm2keygenargs, nil)
	PanicError(err)
	sm2sktxt, err := sm2sk.GetText()
	PanicError(err)
	sm2skpem, err := sm2sk.GetPEM(gmssl.SMS4, "password")
	PanicError(err)
	sm2pkpem, err = sm2sk.GetPublicKeyPEM()
	PanicError(err)

	fmt.Printf("private key as text = %s", sm2sktxt)
	fmt.Printf("private key as pem = %s", sm2skpem)
	fmt.Printf("public key as pem = %s", sm2pkpem)

	sm2pk, err := gmssl.NewPublicKeyFromPEM(sm2pkpem)
	PanicError(err)
	sm3ctx := newSM3DigestContext()
	/* SM2 sign/verification */
	sm2zid, err := sm2pk.ComputeSM2IDDigest("1234567812345678")
	PanicError(err)

	err = sm3ctx.Reset()
	PanicError(err)
	err = sm3ctx.Update(sm2zid)
	PanicError(err)
	err = sm3ctx.Update([]byte("message"))
	PanicError(err)
	digest, err := sm3ctx.Final()
	PanicError(err)

	signature, err := sm2sk.Sign("sm2sign", digest, nil)
	PanicError(err)

	fmt.Printf("sm2sign(sm3(\"message\")) = %x\n", signature)

	err = sm2pk.Verify("sm2sign", digest, signature, nil)
	if err == nil {
		fmt.Printf("sm2 verify success\n")
	} else {
		t.Fatalf("sm2 verify failure")
	}
	/* SM2 encrypt */
	sm2msg := "01234567891123456789212345678931234567894123456789512345678961234567897123"
	sm2encalg := "sm2encrypt-with-sm3"
	sm2ciphertext, err := sm2pk.Encrypt(sm2encalg, []byte(sm2msg), nil)
	PanicError(err)
	sm2plaintext, err := sm2sk.Decrypt(sm2encalg, sm2ciphertext, nil)
	PanicError(err)
	fmt.Printf("sm2enc(\"%s\") = %x\n", sm2plaintext, sm2ciphertext)
	if sm2msg != string(sm2plaintext) {
		t.Fatalf("SM2 encryption/decryption failure")
	}
}

func TestPubKeyGenerate(t *testing.T) {

	/* SM2 key pair operations */
	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := gmssl.GeneratePrivateKey("EC", sm2keygenargs, nil)
	PanicError(err)
	sm2pk_1, err := sm2sk.GetPublicKey()
	PanicError(err)
	sm2pktxt_1, err := sm2pk_1.GetText()
	PanicError(err)

	sm2pkpem, err = sm2sk.GetPublicKeyPEM()
	PanicError(err)
	sm2pk_2, err := gmssl.NewPublicKeyFromPEM(sm2pkpem)
	PanicError(err)
	sm2pktxt_2, err := sm2pk_2.GetText()
	PanicError(err)
	if sm2pktxt_1 != sm2pktxt_2 {
		t.Fatalf("SM2 generate public key checkfailure")
	}

}
func TestLoadPubKeyFromPem(t *testing.T) {
	// Note This test reply on variable Context
	sm2pk, err := gmssl.NewPublicKeyFromPEM(sm2pkpem)
	PanicError(err)
	sm2pktxt, err := sm2pk.GetText()
	PanicError(err)
	sm2pkpem_, err := sm2pk.GetPEM()
	PanicError(err)

	fmt.Printf("public key as text --> %s \n", sm2pktxt)
	fmt.Printf("public key as pem --> %s", sm2pkpem_)
}
func TestCertificate(t *testing.T) {
	/* Certificate */
	certpem := `-----BEGIN CERTIFICATE-----
MIICAjCCAaigAwIBAgIBATAKBggqgRzPVQGDdTBSMQswCQYDVQQGEwJDTjELMAkG
A1UECAwCQkoxCzAJBgNVBAcMAkJKMQwwCgYDVQQKDANQS1UxCzAJBgNVBAsMAkNB
MQ4wDAYDVQQDDAVQS1VDQTAeFw0xNzA2MDEwMDAwMDBaFw0yMDA2MDEwMDAwMDBa
MEYxCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJCSjEMMAoGA1UECgwDUEtVMQswCQYD
VQQLDAJDQTEPMA0GA1UEAwwGYW50c3NzMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0D
QgAEHpXtrYNlwesl7IyPuaHKKHqn4rHBk+tCU0l0T+zuBNMHAOJzKNDbobno6gOI
EQlVfC9q9uk9lO174GJsMLWJJqN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0E
HxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFJsrRYOA
J8gpNq0KK6yuh/Dv9SjaMB8GA1UdIwQYMBaAFH1Dhf9CqQQYHF/8euzcPROIzn0r
MAoGCCqBHM9VAYN1A0gAMEUCIQCjrQ2nyiPqod/gZdj5X1+WW4fGtyqXvXLL3lOF
31nA/gIgZOpHLnvkyggY9VFfEQVp+8t6kewSfxb4eOImSu+dZcE=
-----END CERTIFICATE-----`

	cert, err := gmssl.NewCertificateFromPEM(certpem, "")
	PanicError(err)
	subject, err := cert.GetSubject()
	PanicError(err)
	issuer, err := cert.GetIssuer()
	PanicError(err)
	serial, err := cert.GetSerialNumber()
	PanicError(err)
	certpk, err := cert.GetPublicKey()
	PanicError(err)
	certpktxt, err := certpk.GetText()
	PanicError(err)
	certtxt, err := cert.GetText()
	PanicError(err)

	fmt.Println("Certificate:")
	fmt.Printf("  Subject = %s\n", subject)
	fmt.Printf("  Issuer = %s \n", issuer)
	fmt.Printf("  Serial Number = %s\n", serial)
	fmt.Println(certpktxt)
	fmt.Println(certtxt)
}
func TestSSL(t *testing.T) {
	/* SSL */
	hostname := "its.pku.edu.cn"
	ssl, err := gmssl.NewSSLContext("3.3", "mozilla-cacerts.pem", "")
	PanicError(err)
	conn, err := ssl.Connect(hostname, "443", "ALL")
	PanicError(err)
	result, err := conn.GetVerifyResult()
	PanicError(err)
	if result != 0 {
		t.Fatalf("http://%s certificate verify failure\n", hostname)
	}
	peercert, err := conn.GetPeerCertificate()
	PanicError(err)
	fmt.Println(result)
	peercerttxt, err := peercert.GetText()
	PanicError(err)
	fmt.Println(peercerttxt)
}

func BenchmarkSM2Sign(b *testing.B) {
	b.ReportAllocs()
	/* SM2 key pair operations */
	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := gmssl.GeneratePrivateKey("EC", sm2keygenargs, nil)
	PanicError(err)

	sm2pkpem, err = sm2sk.GetPublicKeyPEM()
	PanicError(err)

	sm2pk, err := gmssl.NewPublicKeyFromPEM(sm2pkpem)
	PanicError(err)

	sm3ctx := newSM3DigestContext()
	/* SM2 sign/verification */

	sm2zid, err := sm2pk.ComputeSM2IDDigest("1234567812345678")
	PanicError(err)
	err = sm3ctx.Reset()
	PanicError(err)
	err = sm3ctx.Update(sm2zid)
	PanicError(err)
	err = sm3ctx.Update([]byte("message"))
	PanicError(err)
	digest, err := sm3ctx.Final()
	PanicError(err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm2sk.Sign("sm2sign", digest, nil)
	}
}

func BenchmarkSM2Verify(b *testing.B) {
	b.ReportAllocs()
	/* SM2 key pair operations */
	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := gmssl.GeneratePrivateKey("EC", sm2keygenargs, nil)
	PanicError(err)

	sm2pkpem, err = sm2sk.GetPublicKeyPEM()
	PanicError(err)

	sm2pk, err := gmssl.NewPublicKeyFromPEM(sm2pkpem)
	PanicError(err)

	sm3ctx := newSM3DigestContext()
	/* SM2 sign/verification */

	sm2zid, err := sm2pk.ComputeSM2IDDigest("1234567812345678")
	PanicError(err)
	err = sm3ctx.Reset()
	PanicError(err)
	err = sm3ctx.Update(sm2zid)
	PanicError(err)
	err = sm3ctx.Update([]byte("message"))
	PanicError(err)
	digest, err := sm3ctx.Final()
	PanicError(err)

	signature, err := sm2sk.Sign("sm2sign", digest, nil)
	PanicError(err)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = sm2pk.Verify("sm2sign", digest, signature, nil)
	}
}

func BenchmarkEcdsaSign(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		_, _, err := ecdsa.Sign(rand.Reader, priv, msg)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkEcdsaVerify(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		ecdsa.Verify(&priv.PublicKey, msg, r, s)
	}
}
