/*
 * Copyright 1995-2020 The Hyperledger-TWGC Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
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

