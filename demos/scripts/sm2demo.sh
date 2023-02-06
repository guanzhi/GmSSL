#!/bin/bash

gmssl sm2keygen -pass 1234 -out sm2.pem -pubout sm2pub.pem

echo hello | gmssl sm2sign -key sm2.pem -pass 1234 -out sm2.sig #-id 1234567812345678
echo hello | gmssl sm2verify -pubkey sm2pub.pem -sig sm2.sig -id 1234567812345678

echo hello | gmssl sm2encrypt -pubkey sm2pub.pem -out sm2.der
gmssl sm2decrypt -key sm2.pem -pass 1234 -in sm2.der

