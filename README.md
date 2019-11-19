## About GmSSL

[![Build Status](https://travis-ci.org/guanzhi/GmSSL.svg?branch=master)](https://travis-ci.org/guanzhi/GmSSL)
[![Build status](https://ci.appveyor.com/api/projects/status/8frwxuwaj4695grq/branch/master?svg=true)](https://ci.appveyor.com/project/zhaoxiaomeng/gmssl/branch/master)


GmSSL is an open source cryptographic toolkit that provide first level support of Chinese national cryptographic algorithms and protocols which are specified in the GM/T serial standards. As a branch of the OpenSSL project, GmSSL provides API level compatibility with OpenSSL and maintains all the functionalities. Existing projects such as Apache web server can be easily ported to GmSSL with minor modification and a simple rebuild. Since the first release in late 2014, GmSSL has been selected as one of the six recommended cryptographic projects by Open Source China and the winner of the 2015 Chinese Linux Software Award.

## Features

 - Support [Chinese GM/T cryptographic standards](http://gmssl.org/docs/standards.html).
 - Support [hardware cryptographic modules from Chinese vendors](http://www.sca.gov.cn/sca/zxfw/cpxx.shtml).
 - With commercial friendly open source [license](http://gmssl.org/docs/licenses.html).
 - Maintained by the [crypto research group of Peking University](http://infosec.pku.edu.cn).

## Supported Algorithms

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
 - OTP (One-Time Password) based on SM3/SM4 (GM/T 0021-2012)
 - Encoding: Base58

OpenSSL algorithms such as ECDSA, RSA, AES, SHA-1 are all still available in GmSSL.

## GM/T Protocols

The GM/T standards cover 2 protocols:

 - SSL VPN Protocol  (GM/T 0024-2014)
 - IPSec VPN Protocol (GM/T 0022-2014)

The GM/T 0024-2014 SSL VPN protocol is different from IETF TLS in the follows aspects:

 - Current version of TLS is 1.3 (0x0304) while GM/T SSL version is 1.1 (0x0102).
 - The handshake protocol of GM/T SSL is different from TLS handshake.
 - There is an optional different record protocol in GM/T SSL designed for VPN applications.
 - GM/T SSL has 12 ciphersuites, some of these ciphers do not provide forward secrecy.

GM/T 0024-2014 Ciphersuites:

```
 1. {0xe0,0x01} GMTLS_SM2DHE_SM2SIGN_WITH_SM1_SM3
 2. {0xe0,0x03} GMTLS_SM2ENC_WITH_SM1_SM3
 3. {0xe0,0x05} GMTLS_SM9DHE_SM9SIGN_WITH_SM1_SM3
 4. {0xe0,0x07} GMTLS_SM9ENC_WITH_SM1_SM3
 5. {0xe0,0x09} GMTLS_RSA_WITH_SM1_SM3
 6. {0xe0,0x0a} GMTLS_RSA_WITH_SM1_SHA1
 7. {0xe0,0x11} GMTLS_SM2DHE_SM2SIGN_WITH_SMS4_SM3
 8. {0xe0,0x13} GMTLS_SM2ENC_WITH_SMS4_SM3
 9. {0xe0,0x15} GMTLS_SM9DHE_SM9SIGN_WITH_SMS4_SM3
10. {0xe0,0x17} GMTLS_SM9ENC_WITH_SMS4_SM3
11. {0xe0,0x19} GMTLS_RSA_WITH_SMS4_SM3
12. {0xe0,0x1a} GMTLS_RSA_WITH_SMS4_SHA1
```

GmSSL supports the standard TLS 1.2 protocol with SM2/SM3/SM4 ciphersuites and the GM/T SSL VPN protocol and ciphersuites. Currently the following ciphersuites are supported:

```
ECDHE-SM2-WITH-SMS4-SM3
ECDHE-SM2-WITH-SMS4-SHA256
```

## APIs

Except for the native C interface and the `gmssl` command line, GmSSL also provide the following interfaces:

 - Java: crypto, X.509 and SSL API through JNI (Java Native Interface).
 - Go: crypto, X.509 and SSL API through CGO.
 - SKF C API: GM/T 0016-2012 Smart token cryptography application interface specification.
 - SDF C API: GM/T 0018-2012 Interface specifications of cryptography device application.
 - SAF C API: GM/T 0019-2012 Universal cryptography service interface specification.
 - SOF C/Java API: GM/T 0020-2012 Certificate application integrated service interface specification.

## Supported Cryptographic Hardwares

 - USB-Key through the SKF ENGINE and the SKF API.
 - PCI-E card through the SDF ENGINE and the SDF API.
 - GM Instruction sets (SM3/SM4) through the GMI ENGINE.

## Quick Start

This short guide describes the build, install and typical usage of the `gmssl` command line tool. Visit http://gmssl.org for more documents.

Download ([GmSSL-master.zip](https://github.com/guanzhi/GmSSL/archive/master.zip)), uncompress it and go to the source code folder. On Linux and OS X, run the following commands:

 ```sh
 $ ./config
 $ make
 $ sudo make install
 ```

After installation you can run `gmssl version -a` to print detailed information.

The `gmssl` command line tool supports SM2 key generation through `ecparam` or `genpkey` option, supports SM2 signing and encryption through `pkeyutl` option, supports SM3 through `sm3` or `dgst` option, and supports SM4 through `sms4` or `enc` option.

The following are some examples.

SM3 digest generation:

```
$ echo -n "abc" | gmssl sm3
(stdin)= 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

SM4 encryption and decryption:

```sh
$ gmssl sms4 -in README.md -out README.sms4
$ gmssl sms4 -d -in README.sms4
```

ZUC/ZUC256 encryption and decryption:

```sh
$ gmssl zuc -in README.md -out README.zuc
$ gmssl zuc -d -in README.zuc
$ gmssl zuc256 -in README.md -out README.zuc256
$ gmssl zuc256 -d -in README.zuc256
```

SM2 private key generation:

```sh
$ gmssl sm2 -genkey -out skey.pem
```

Derive the public key from the generated SM2 private key:

```sh
$ gmssl sm2 -pubout -in skey.pem -out vkey.pem
```

SM2 signature generation and verification:

```sh
$ gmssl sm2utl -sign -in README.md -inkey skey.pem -out README.md.sig
$ gmssl sm2utl -verify -in README.md -pubin -inkey vkey.pem -sigfile README.md.sig
```

Generate SM2 encryption key pair and do SM2 public key encyption/decryption. It should be noted `pkeyutl -encrypt` should only be used to encrypt short messages such as session key and passphrase.

```sh
$ gmssl sm2 -genkey -out dkey.pem
$ gmssl sm2 -pubout -in dkey.pem -out ekey.pem
$ echo "Top Secret" | gmssl sm2utl -encrypt -pubin -inkey ekey.pem -out ciphertext.sm2
$ gmssl sm2utl -decrypt -inkey dkey.pem -in ciphertext.sm2
```

Identity-based encryption with SM9

```sh
$ echo "Message" | gmssl pkeyutl -encrypt -pubin -inkey params.pem -pkeyopt id:Alice -out ciphertext.der
$ gmssl pkeyutl -decrypt -inkey sm9key.pem -in ciphertext.der
```

Self-signed SM2 certificate generation:

```sh
$ gmssl req -new -x509 -key skey.pem -out cert.pem
```

TLS/DTLS with SM2 ciphersuites:

```sh
$ gmssl s_server [-tls1_2|-dtls1_2] -port 443 -cipher SM2 -key sm2key.pem -cert sm2cert.pem &
$ gmssl s_client [-tls1_2|-dtls1_2] -connect localhost:443 -cipher SM2 -CAfile cacert.pem
```

