#!/bin/bash -x

KEY_FILE=user.key
REQ_FILE=user.req
CERT_FILE=user.pem

gmssl ecparam -genkey -name sm2p256v1 -text -out $KEY_FILE
gmssl req -new -key $KEY_FILE -out $REQ_FILE
gmssl ca -out $CERT_FILE  -outdir . -infiles $REQ_FILE
gmssl pkcs12 -export -out user.pfx -in $CERT_FILE -inkey $KEY_FILE -certfile ./demoCA/cacert.pem

