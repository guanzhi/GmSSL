#!/bin/bash

DIR=demoCA

rm -fr $DIR
mkdir $DIR
mkdir $DIR/certs
mkdir $DIR/crl
mkdir $DIR/newcerts
mkdir $DIR/private/
touch $DIR/index.txt
touch $DIR/crlnumber
touch $DIR/private/.rand
echo 01 > $DIR/serial

gmssl ecparam -genkey -name sm2p256v1 -text -out $DIR/private/cakey.pem
gmssl req -new -x509 -days 3650 -key $DIR/private/cakey.pem -out $DIR/cacert.pem
gmssl x509 -text -noout -in $DIR/cacert.pem

