#!/bin/bash -x
# Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.

gmssl=gmssl

echo "SSL/TLS Cipher Suites:"
$gmssl ciphers
echo
$gmssl ciphers -v
echo
$gmssl ciphers -V
echo

# show detailed information of a cipher suite
$gmssl ciphers -V SM2-WITH-SMS4-SM3

# show if the specified cipher is supported
$gmssl ciphers -s -tls1 SM2-WITH-SMS4-SM3

echo "Supported Cipher Suites:"
$gmssl ciphers -s
echo

echo "TLS 1.2 Cipher Suites:"
$gmssl ciphers -tls1_2
echo

echo "PSK (Pre-Shared Key) Cipher Suites:"
$gmssl ciphers -psk
echo

echo "SRP (Secure Remote Password) Cipher Suites:"
$gmssl ciphers -srp
echo
