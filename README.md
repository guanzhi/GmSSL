## About GmSSL

[![Build Status](https://travis-ci.org/guanzhi/GmSSL.svg?branch=master)](https://travis-ci.org/guanzhi/GmSSL)

GmSSL is an open source cryptographic toolbox that supports SM2 / SM3 / SM4 / SM9 and other national secret (national commercial password) algorithm, SM2 digital certificate and SM2 certificate based on SSL / TLS secure communication protocol to support the national security hardware password device , To provide in line with the national standard programming interface and command line tools, can be used to build PKI / CA, secure communication, data encryption and other standards in line with national security applications. The GmSSL project is a branch of the [OpenSSL](https://www.openssl.org)project and is compatible with OpenSSL. So GmSSL can replace the application of OpenSSL components, and make the application automatically with national security capabilities. The GmSSL project utilizes a business-friendly BSD open source license, open source and can be used for closed source commercial applications. GmSSL project by the Peking University [Guan Zhi](http://infosec.pku.edu.cn/~guanzhi/)deputy researcher of the cryptography research group development and maintenance, the project source code hosted in [GitHub](https://github.com /guanzhi/GmSSL). Since its release in 2014, GmSSL has been deployed and applied in multiple projects and products, and has won the second prize of the "One Cup" China Linux Software Contest in 2015 (the highest award) and [Open Source China](https://www.oschina.net/p/GmSSL) password class recommended items. The core goal of the GmSSL project is to promote the construction of cyberspace security through open source cryptography.

In 2014, the GmSSL (http://gmssl.org) project is released to provide open source implementations of Chinese GM cryptography standards.
Now, GmSSL is the most popular open source GM cryptography toolkit in China.
GmSSL team are helping big companies to transfer from International standards to national standards



## Latest News

- February 15, 2017  rename master to gmssl-v1，current master branch migrate to OpenSSL-1.1.0。
- February 12, 2017 Java wrapper support for full crypto library  [GmSSL-Java-Wrapper](http://gmssl.org/docs/java-api.html)
- January 18, 2017 Updated the project home page
- [More ...](http://gmssl.org/docs/changelog.html)

## Algorithm

 - ZUC stream cipher, defined in GM/T 0001-2012
 - SM4 block cipher with 128-bit key length and 128-bit block size, defined in GM/T 0002-2012
 - SM3 Digest Algorithm with 256-bit digest length and 512-bit block size, defined in GM/T 0004-2012
 - SM2 ellptic curve cryptography and 256-bit prime field recommended domain parameters, defined in GM/T 0003-2012
 - SM9 pairing-based cryptography and recommended BN-curve, defined in GM/T 0046-2016
 - SM1 block cipher with 128-bit key length and 128-bit block size, only provided with chip
 - SSF33 block cipher with 128-bit key length and 128-bit block size, only provided by chip

## Programming Interfaces

 - SKF C API (GM/T 0016-2012) Smart token cryptography application interface specification.
 - SDF C API (GM/T 0018-2012) Interface specifications of cryptography device application.
 - SAF C API (GM/T 0019-2012) Universal cryptography service interface specification.
 - SOF C/Java API (GM/T 0020-2012) Certificate application integrated service interface specification.

## Protocols

 - One-time password scheme based on SM3 and SM4
 - SSL VPN protocol with RSA/SM2/SM9-SM4-SM3 cipher suites
 - IPSec VPN protocol

## Features

 - Support Chinese
 - Full support of Chinese GM Cryptography Standards
 - Support Chinese cryptographic hardwares (HSMs).
 - Commercial friendly BSD-style open source license.
 - Support SSL protocols
 - Compatible with OpenSSL, all OpenSSL functionalities preserved.

The secret algorithm is the abbreviation of the national commercial cryptographic algorithm. Since 2012, the National Password Authority to the "People's Republic of China password industry standard" approach, have announced the SM2 / SM3 / SM4 and other cryptographic algorithm standards and application specifications. Which "SM" on behalf of "business secret", that is used for commercial, not involving state secrets of the password technology. SM2 is a public key cryptography algorithm based on elliptic curve cryptography, including digital signature, key exchange and public key encryption. It is used to replace international algorithms such as RSA / Diffie-Hellman / ECDSA / ECDH. SM3 is password hash algorithm, SM4 is a block cipher used to replace DES / AES and other international algorithms. SM9 is an identity-based cryptographic algorithm that can replace PKI / CA based on digital certificate. By deploying the secret algorithm, you can reduce the security risks caused by weak passwords and bug implementations and the overhead of deploying PKI / CA.

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

