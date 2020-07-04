/*
 * Copyright (c) 2017 - 2019 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* +build cgo */
package gmssl

/*
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sm9.h>
#include <openssl/is_gmssl.h>
*/
import "C"

import (
	"unsafe"
	"errors"
	"runtime"
)

func GetPublicKeyAlgorithmNames() []string {
	return []string{
		"DH",
		"DSA",
		"RSA",
		"EC",
		"X25519",
	}
}

func GetPairingNames() []string {
	return []string{
		"sm9bn256v1",
	}
}

func GetSchemeNames() []string {
	return []string{
		"sm9sign",
		"sm9encrypt",
		"sm9keyagreement",
	}
}

func GetHash1Names() []string {
	return []string{
		"sm9hash1_with_sm3",
		"sm9hash1_with_sha256",
	}
}

func GetSignAlgorithmNames() []string {
	return []string{
		"sm3",
	}
}

func GetEncryptionAlgorithmNames() []string {
	return []string{
		"sm9encrypt_with_sm3_xor",
	}
}

type SM9MasterSecret struct {
	msk *C.SM9MasterSecret
}

type SM9PublicParameters struct {
	mpk *C.SM9PublicParameters
}

type SM9PrivateKey struct {
	sk *C.SM9PrivateKey
}

type SM9PublicKey struct {
	pk *C.SM9PublicKey
}


func SM9Setup(pairing string, scheme string, hash1 string) (*SM9PublicParameters, *SM9MasterSecret, error) {
	return nil, nil, nil;
}

func NewSM9MasterSecretFromPEM(pem string, pass string) (*SM9MasterSecret, error) {
	return nil, nil
}

func (msk *SM9MasterSecret) GetPEM(cipher string, pass string) (string, error) {
	return nil, nil;
}

func (msk *SM9MasterSecret) GetPublicParametersPEM() (string, error) {
	return nil, nil;
}

func (msk *SM9MasterSecret) GetText() (string, error) {
	return nil, nil;
}

func NewSM9PublicParametersFromPEM(pem string) (*SM9PublicParameters, error) {
	return nil, nil
}

func (mpk *SM9PublicParameters) GetPEM() (string, error) {
	return nil, nil;
}

func (mpk *SM9PublicParameters) GetText() (string, error) {
	return nil, nil;
}

func (msk *SM9MasterSecret) ExtractPrivateKey(id string) (*SM9PrivateKey, error) {
	return nil, nil
}

func (mpk *SM9PublicParameters) ExtractPublicKey(id string) (*SM9PublicKey, error) {
	return nil, nil
}

func NewSM9PrivateKeyFromPEM(pem string, pass string) (*SM9PrivateKey, error) {
	return nil, nil
}

func (sk *SM9PrivateKey) GetPEM(cipher string, pass string) (string, error) {
	return nil, nil
}

func (sk *SM9PrivateKey) GetPublicKeyPEM() (string, error) {
	return nil, nil
}

func (sk *SM9PrivateKey) GetText() (string, error) {
	return nil, nil
}

func NewSM9PublicKeyFromPEM(pem string) (*SM9PublicKey, error) {
	return nil, nil
}

func (pk *SM9PublicKey) GetPEM() (string, error) {
	return nil, nil
}

func (pk *SM9PublicKey) GetText() (string, error) {
	return nil, nil
}

func (sk *SM9PrivateKey) Sign(alg string, data []byte) ([]byte, error) {
	return nil, nil
}

func (mpk *SM9PublicParameters) Verify(alg string, data []byte, sig []byte, id string) (error) {
	return nil
}

func (mpk *SM9PublicParameters) Encrypt(alg string, in []byte, id string) ([]byte, error) {
	return nil, nil
}

func (sk *SM9PrivateKey) Decrypt(alg string, in []byte) ([]byte, error) {
	return nil, nil
}

