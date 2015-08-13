OpenSSL-SM
==========

The OpenSSL integrated with Chinese national cryptography standard:

 * SM2: Elliptic curve cryptography, including signature scheme, encryption and key agreement, use the modified `ECDSA` module.
 * SM3: Hash algorithm with 256-bit digest length, use `EVP_sm3()`
 * SM4: or SMS4, a Feistel-style block cipher with 128-bit key length and 128-bit block size, use `EVP_sms4_ecb()`, `EVP_sms4_cbc()`, `EVP_sms4_cfb()`, `EVP_sms4_ofb()`.


