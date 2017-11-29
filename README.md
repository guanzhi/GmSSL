## About GmSSL

[![Build Status](https://travis-ci.org/guanzhi/GmSSL.svg?branch=master)](https://travis-ci.org/guanzhi/GmSSL)

GmSSL is an open source cryptographic toolkit that provide first level support of Chinese national cryptographic algorithms and protocols which specified in the GM/T serial standards. As a branch of the OpenSSL project, GmSSL provides API level compatibility with OpenSSL and maintains all the functionalities. Existing projects such as Apache web server can be easily ported to GmSSL with minor modification and simple rebuild. Since the first release in late 2014, GmSSL has been selected as one of the six recommended cryptographic projects by Open Source China and the winner of the 2015 Chinese Linux Software Award.

## Features

 - Support [Chinese GM/T cryptographic standards](http://gmssl.org/docs/standards.html).
 - Support [hardware cryptographic modules from Chinese vendors](http://www.sca.gov.cn/sca/zxfw/cpxx.shtml).
 - With commercial friendly open source [license](http://gmssl.org/docs/licenses.html).

## GM/T Algorithms

GmSSL will support all the following GM/T cryptographic algorithms:

 - SM3 (GM/T 0004-2012): cryptographic hash function with 256-bit digest length.
 - SM4 (GM/T 0002-2012): block cipher with 128-bit key length and 128-bit block size, also named SMS4.
 - SM2 (GM/T 0003-2012): elliptic curve cryptographic schemes including digital signature scheme, public key encryption, (authenticated) key exchange protocol and one recommended 256-bit prime field curve `sm2p256v1`.
 - SM9 (GM/T 0044-2016): pairing-based cryptographic schemes including identity-based digital signature, encryption, (authenticated) key exchange protocol and one 256-bit recommended BN curve.
 - ZUC (GM/T 0001-2012): stream cipher, with 128-EEA3 encryption algorithm and 128-EIA3 integrity algorithm.
 - SM1 and SSF33: block ciphers with 128-bit key length and 128-bit block size without public specification, only provided with chip.
 
GmSSL supports many useful cryptographic algorithms and schemes:

 - Public-key schemes: Paillier, ECIES (Elliptic Curve Integrated Encryption Scheme)
 - Pairing-based cryptography: BF-IBE, BB1-IBE
 - Block ciphers and modes: Serpent, Speck
 - Block cipher modes: FPE (Format-Preserver Encryption)
 - Encoding: Base58

OpenSSL algorithms such as ECDSA, RSA, AES, SHA-1 are all remained in GmSSL.

## GM/T Protocols

| #    | GM/T Name       | GmSSL Name                     |             |
| ---- | --------------- | ------------------------------ | ----------- |
| 1    | `ECDHE_SM1_SM3` | `SM2DHE_SM2SIGN_WITH_SM1_SM3`  | {0xe0,0x01} |
| 2    | `ECC_SM1_SM3`   | `SM2ENC_WITH_SM1_SM3`          | {0xe0,0x03} |
| 3    | `IBSDH_SM1_SM3` | `SM9DHE_SM9SIGN_WITH_SM1_SM3`  | {0xe0,0x05} |
| 4    | `IBC_SM1_SM3`   | `SM9ENC_WITH_SM1_SM3`          | {0xe0,0x07} |
| 5    | `RSA_SM1_SM3`   | `RSA_WITH_SM1_SM3`             | {0xe0,0x09} |
| 6    | `RSA_SM1_SHA1`  | `RSA_WITH_SM1_SHA1`            | {0xe0,0x0a} |
| 7    | `ECDHE_SM4_SM3` | `SM2DHE_SM2SIGN_WITH_SMS4_SM3` | {0xe0,0x11} |
| 8    | `ECC_SM4_SM3`   | `SM2ENC_WITH_SMS4_SM3`         | {0xe0,0x13} |
| 9    | `IBSDH_SM4_SM3` | `SM3DHE_SM9SIGN_WITH_SMS4_SM3` | {0xe0,0x15} |
| 10   | `IBC_SM4_SM3`   | `SM9ENC_WITH_SMS4_SM3`         | {0xe0,0x17} |
| 11   | `RSA_SM4_SM3`   | `RSA_WITH_SMS4_SM3`            | {0xe0,0x19} |
| 12   | `RSA_SM4_SHA1`  | `RSA_WITH_SMS4_SM3`            | {0xe0,0x1a} |

TLS 1.2 cipher suites:

## APIs

Except for the native C interface and the `gmssl` command line, GmSSL also provide the following interfaces:

 - **SKF** C API GM/T 0016-2012 Smart token cryptography application interface specification.
 - **SDF** C API GM/T 0018-2012 Interface specifications of cryptography device application.
 - **SAF** C API GM/T 0019-2012 Universal cryptography service interface specification.
 - **SOF** C/Java API GM/T 0020-2012 Certificate application integrated service interface specification.
 - **Java** crypto, X.509 and SSL API through JNI (Java Native Interface).
 - **Go** crypto, X.509 and SSL API through CGO.

## Supported Cryptographic Hardwares

 - USB-Key through **SKF ENGINE** and the SKF API.
 - PCI-E card through **SDF ENGINE** and the SDF API.
 - GM Instruction sets (SM3/SM4) through **GMI ENGINE**.

## Quick Start

This short guide describes the build, install and typical usage of the `gmssl` command line tool. Visit http://gmssl.org for more documents.

1. Download the source code ([GmSSL-master.zip](https://github.com/guanzhi/GmSSL/archive/master.zip)) and uncompress the ZIP file.
2. Compile and install on Linux and Mac OS X

```sh
$ ./config
$ make
$ sudo make install
```
   Compile and install on Windows

```bash
> perl Configure VC-WIN32
> nmake
> nmake install
```

​	After installation, you can run `gmssl version -a` to print the detailed information of gmssl.

3. Encrypt and decrypt with SM4 and password

```sh
$ echo -n abc | gmssl sms4 -out ciphertext.bin
$ gmssl sms4 -d -in ciphertext.sms4
```

4. Generate SM3 digest

```
$ echo -n abc | gmssl sm3
(stdin)= 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

5. Generate SM2 keypair

```sh
$ gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -pkeyopt ec_param_enc:named_curve -out skey.pem
$ gmssl pkey -pubout -in skey.pem -out pkey.pem
```

6. Generate SM2 signature (in DER format) and verify

```sh
$ gmssl pkeyutl -sign -pkeyopt ec_scheme:sm_scheme -inkey skey.pem -in msg.txt -out msg.sig
$ gmssl pkeyutl -verify -pkeyopt ec_scheme:sm_scheme -pubin -inkey vrfykey.pem -in <yourfile> -sigfile <yourfile>.sig
```

7. Do public key encryption and decryption

```sh
$ gmssl pkeyutl -sign -pkeyopt ec_scheme:sm_scheme -inkey skey.pem -in msg.txt -out msg.sig
$ gmssl pkeyutl -verify -pkeyopt ec_scheme:sm_scheme -pubin -inkey vrfykey.pem -in <yourfile> -sigfile <yourfile>.sig
```

8. Generate a self-signed certificate from private key

```sh
$ gmssl req -new -x509 -key skey.pem -out cert.pem
```

