#!/bin/bash -x

CURVE=secp192k1
KEY_FILE=user.key
REQ_FILE=user.req
CERT_FILE=user.pem

#openssl ecparam -genkey -name $CURVE -text -out $KEY_FILE
openssl genrsa 1024 -text > $KEY_FILE
openssl req -new -key $KEY_FILE -out $REQ_FILE
openssl ca -out $CERT_FILE  -outdir . -infiles $REQ_FILE
openssl pkcs12 -export -out user.pfx -in $CERT_FILE -inkey $KEY_FILE -certfile .demoCA/cacert.pem

#rm -f $KEY_FILE
#rm -f $REQ_FILE
#rm -f $CERT_FILE

