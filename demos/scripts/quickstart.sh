#!/bin/bash
# Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.

gmssl=gmssl

echo -n "abc" | $gmssl sm3
echo "SM4 Decrypted Successfully" | $gmssl sms4 -e -K 1234567890ABCDEF1234567890ABCDEF -iv 11223344556677889900AABBCCDDEEFF -out README.sms4
$gmssl sms4 -d -K 1234567890ABCDEF1234567890ABCDEF -iv 11223344556677889900AABBCCDDEEFF -in README.sms4 -out README-2.md
$gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -pkeyopt ec_param_enc:named_curve -out skey.pem
$gmssl pkey -pubout -in skey.pem -out vkey.pem
$gmssl pkeyutl -sign -pkeyopt ec_scheme:sm2 -inkey skey.pem -in README.md -out README.md.sig
$gmssl pkeyutl -verify -pkeyopt ec_scheme:sm2 -pubin -inkey vkey.pem -in README.md -sigfile README.md.sig
$gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -pkeyopt ec_param_enc:named_curve -out dkey.pem
$gmssl pkey -pubout -in dkey.pem -out ekey.pem
echo "Ciphertext Decrypted Successfully" | $gmssl pkeyutl -encrypt -pkeyopt ec_scheme:sm2 -pubin -inkey ekey.pem -out ciphertext.sm2
$gmssl pkeyutl -decrypt -pkeyopt ec_scheme:sm2 -inkey dkey.pem -in ciphertext.sm2
#$gmssl req -new -x509 -key skey.pem -out cert.pem
