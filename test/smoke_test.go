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
	"fmt"
	"github.com/Hyperledger-TWGC/Gm-Go/gmssl"
	"testing"
)

func TestVersion(t *testing.T) {
	versions := gmssl.GetVersions()
	fmt.Println("GmSSL Versions:")
	for _, version := range versions {
		fmt.Println(" " + version)
	}
}
func TestDigestAlgorithms(t *testing.T) {
	fmt.Print("Digest Algorithms:")
	digests := gmssl.GetDigestNames()
	for _, digest := range digests {
		fmt.Print(" " + digest)
	}
}
func TestCiphers(t *testing.T) {
	fmt.Print("Ciphers:")
	ciphers := gmssl.GetCipherNames()
	for _, cipher := range ciphers {
		fmt.Print(" " + cipher)
	}
}
func TestPublicKeyAlgorithms(t *testing.T) {
	fmt.Println("Public Key Algorithms:")
	pkeyAlgs := gmssl.GetPublicKeyAlgorithmNames()
	for _, pkeyAlg := range pkeyAlgs {
		fmt.Print(" " + pkeyAlg + ":")
		signAlgs, error := gmssl.GetSignAlgorithmNames(pkeyAlg)
		PanicError(error)
		for _, sign_alg := range signAlgs {
			fmt.Print(" " + sign_alg)
		}
		pkeyEncs, error := gmssl.GetPublicKeyEncryptionNames(pkeyAlg)
		PanicError(error)
		for _, pkeyEnc := range pkeyEncs {
			fmt.Print(" " + pkeyEnc)
		}
		deriveAlgs, error := gmssl.GetDeriveKeyAlgorithmNames(pkeyAlg)
		PanicError(error)
		for _, deriveAlg := range deriveAlgs {
			fmt.Print(" " + deriveAlg)
		}
		fmt.Println("")
	}
}
func TestEngines(t *testing.T) {
	/* Engines */
	fmt.Print("Engines:")
	engines := gmssl.GetEngineNames()
	for _, engine := range engines {
		fmt.Print(" " + engine)
	}
}
