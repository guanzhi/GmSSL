#!/bin/bash


gmssl=/usr/local/bin/gmssl
paramfile=ecparam.pem
keyfile=eckey.pem
pubkeyfile=ecpubkey.pem
pkeyopt="-pkeyopt ec_paramgen_curve:sm2p256v1"


echo -n abc | $gmssl dgst -sm3
echo -n abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd | gmssl dgst -sm3

#$gmssl version
#$gmssl ecparam -list_curves | grep sm2
#$gmssl ecparam -text -noout -name sm2p256v1 -param_enc explicit

$gmssl genpkey -genparam -algorithm SM2 $ecpkeyopt -out $paramfile
#$gmssl genpkey -algorithm EC $pkeyopt -out $keyfile
#$gmssl pkey -text -noout -in $keyfile
#$gmssl pkey -in $keyfile -pubout -out $pubkeyfile
#$gmssl pkey -text -noout -pubin -in $pubkeyfile

