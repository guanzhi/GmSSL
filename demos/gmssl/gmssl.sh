#!/bin/bash

gmssl=../../apps/gmssl
paramfile=ecparam.pem
keyfile=eckey.pem
pubkeyfile=ecpubkey.pem
pkeyopt="-pkeyopt ec_paramgen_curve:sm2p256v1"


#echo -n abc | $gmssl dgst -sm3
#echo -n abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd | gmssl dgst -sm3

#$gmssl version
#$gmssl ecparam -list_curves | grep sm2
#$gmssl ecparam -text -noout -name sm2p256v1 -param_enc explicit
#$gmssl genpkey -genparam -algorithm EC -out sm2p256v1.pem -pkeyopt ec_paramgen_curve:sm2p256v1 -pkeyopt ec_param_enc:named_curve
$gmssl genpkey -algorithm EC -out sm2key.pem -pkeyopt ec_paramgen_curve:sm2p256v1 -pkeyopt ec_param_enc:named_curve
#$gmssl pkey -text -noout -in sm2key.pem
#$gmssl pkey -in sm2key.pem -pubout -out sm2pubkey.pem
#$gmssl pkey -text -noout -pubin -in $pubkeyfile

echo hello | $gmssl pkeyutl -sign -inkey sm2key.pem -pkeyopt ec_sign_algor:sm2 > sm2sig.der

echo hello | $gmssl pkeyutl -verify -inkey sm2key.pem -sigfile sm2sig.der -pkeyopt ec_sign_algor:sm2

echo hello | $gmssl pkeyutl -encrypt -inkey sm2key.pem -pkeyopt ec_encrypt_algor:sm2 > sm2ciphertext.bin


cat sm2ciphertext.bin | $gmssl pkeyutl -decrypt -inkey sm2key.pem -pkeyopt ec_encrypt_algor:sm2

$gmssl req -new -x509 -days 3650 -key sm2key.pem -out cert.pem
#$gmssl x509 -text -noout -in $DIR/cacert.pem
