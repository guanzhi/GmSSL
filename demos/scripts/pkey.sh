#!/bin/bash -x

gmssl=~/code/github/gmssl/apps/gmssl

$gmssl genpkey -genparam -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -pkeyopt ec_param_enc:named_curve -out sm2p256v1.pem
$gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -pkeyopt ec_param_enc:named_curve -out sm2key.pem
$gmssl pkey -text -noout -in sm2key.pem
$gmssl pkey -pubout -in sm2key.pem -out sm2pubkey.pem
$gmssl pkey -text -noout -pubin -in sm2pubkey.pem

message="This is the message to be signed."
sigfile="sm2sig.der"
echo $message | $gmssl pkeyutl   -sign -pkeyopt ec_scheme:sm2        -inkey sm2key.pem        -out $sigfile
echo $message | $gmssl pkeyutl -verify -pkeyopt ec_scheme:sm2 -pubin -inkey sm2pubkey.pem -sigfile $sigfile

echo "Message : $message"
echo "Signature :"
$gmssl asn1parse -inform DER -in $sigfile

plaintext="This is the plaintext to be encrypted."
ciphertext=ciphertext.der
echo $plaintext | $gmssl pkeyutl -encrypt -pkeyopt ec_scheme:sm2 -inkey sm2key.pem -out $ciphertext
cat $ciphertext | $gmssl pkeyutl -decrypt -pkeyopt ec_scheme:sm2 -inkey sm2key.pem

echo $plaintext
$gmssl asn1parse -inform DER -in $ciphertext
