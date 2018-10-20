#!/bin/bash -x
# Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.

gmssl=gmssl

echo -n "abc" | $gmssl sm3
echo -n "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" | $gmssl sm3
echo -n "abc" | $gmssl dgst -sm3 -binary -out sm3dgst.bin
echo -n "abc" | $gmssl dgst -sm3 -hmac "hmackeystring"

# digest and sign/verify
filename=dgst.sh
$gmssl dgst -sm3 -sign sm2key.pem -out $filename.sig $filename
$gmssl dgst -sm3 -verify sm2pubkey.pem -signature $filename.sig $filename

# cmac
echo hello | $gmssl dgst -sm3 -mac hmac -macopt key:ehllo

# engine

