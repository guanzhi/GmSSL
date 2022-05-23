#!/bin/bash

gmssl sm9setup -alg sm9sign -pass 1234 -out sign_msk.pem -pubout sign_mpk.pem
gmssl sm9keygen -alg sm9sign -in sign_msk.pem -inpass 1234 -id alice -out alice.pem -outpass 1234
echo hello | gmssl sm9sign -key alice.pem -pass 1234  -out hello.sig
echo hello | gmssl sm9verify -pubmaster sign_mpk.pem -id alice -sig hello.sig

gmssl sm9setup -alg sm9encrypt -pass 1234 -out enc_msk.pem -pubout enc_mpk.pem
gmssl sm9keygen -alg sm9encrypt -in enc_msk.pem -inpass 1234 -id bob -out bob.pem -outpass 1234
echo hello | gmssl sm9encrypt -pubmaster enc_mpk.pem -id bob -out hello.der
gmssl sm9decrypt -key bob.pem -pass 1234 -id bob -in hello.der

