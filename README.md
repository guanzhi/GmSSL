OpenSSL-SM
==========

The OpenSSL integrated with Chinese national cryptography standard:

 * SM2: Elliptic curve cryptography, including signature scheme, encryption and key agreement.
 * SM3: Hash algorithm with 256-bit digest length.
 * SM4: or SMS4, a Feistel-style block cipher with 128-bit key length and 128-bit block size.

The first release only add SM2 signature scheme, which modify the ECDSA implementation of OpenSSL.
In the future release the SM2 will be changed to stand alone METHOD modules.
SM3 will be provided as a EVP_MD() module and SM4 will be provided as multiple EVP_CIPHER() modules.


