#!/bin/bash
# Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.

gmssl=gmssl

echo "Commands:"
$gmssl list -commands
echo

echo "Digest Commands:"
$gmssl list -digest-commands
echo

echo "Digest Algorithms:"
$gmssl list -digest-algorithms
echo

echo "Ciphers Commands:"
$gmssl list -cipher-commands
echo

echo "Cipher Algorithms:"
$gmssl list -cipher-algorithms
echo

echo "Public Key Algorithms:"
$gmssl list -public-key-algorithms
echo

# FIXME: gmssl disabled features are not listed!
$gmssl list -disabled
echo
