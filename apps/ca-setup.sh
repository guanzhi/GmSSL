#!/bin/bash

CURVE=prime256v1
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

#openssl ecparam -genkey -name $CURVE -text -out $DIR/private/cakey.pem

openssl genrsa 2048 -text > $DIR/private/cakey.pem
openssl req -new -x509 -days 3650 -key $DIR/private/cakey.pem -out $DIR/cacert.pem
openssl x509 -text -noout -in $DIR/cacert.pem

