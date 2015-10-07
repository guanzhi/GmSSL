#!/bin/bash

PIN=123456
PUK=654321
P11LIB=/usr/local/lib/opensc-pkcs11.so
REQFILE=req.pem
USERNAME="John Doe"

echo " *** Erase card ***"
pkcs15-init --erase-card --verbose

echo " *** Initialization ***"
pkcs15-init				\
	--create-pkcs15			\
	--profile pkcs15+onepin 	\
	--pin $PIN 			\
	--puk $PUK			\
	--label "Personal Crypto Token"	\
	--verbose

echo " *** Generate Key Pair ***"
pkcs11-tool 				\
	--keypairgen			\
	--module $P11LIB		\
	--login --pin $PIN		\
	--key-type rsa:2048		\
	--usage-sign			\
	--subject $USERNAME		\
	--label "Private Key"

KEYID=`pkcs11-tool --module $P11LIB --list-objects | grep "ID"  | awk '{ print $2}'`


echo " *** Generate Certificate Request ***"
openssl req				\
	-new				\
	-engine pkcs11 			\
	-config openssl.conf		\
	-keyform engine			\
	-key 1:$KEYID			\
	-subj "/C=CN/ST=Beijing/L=Beijing/O=PKU/OU=Infosec/CN=$1/emailAddress=$1@pku.edu.cn"	\
	-out $REQFILE

openssl req -in $REQFILE -text

CERTFILE=user.pem
CERTDER=user.der

echo " *** Sign Certificate ***"
openssl ca -batch -out $CERTFILE -notext -outdir . -infiles $REQFILE
openssl x509 -in $CERTFILE -outform DER -out $CERTDER

echo " *** Import Certificate to Token ***"
pkcs11-tool --write-object $CERTDER	\
	--module $P11LIB		\
	--login --pin $PIN		\
	--label Certificate		\
	--type cert			

echo " *** Show Token Info ***"
pkcs11-tool --list-token-slots		\
	--module $P11LIB

pkcs11-tool --list-objects		\
	--module $P11LIB		\
	--login --pin $PIN	

openssl x509 -in $CERTFILE -text -noout


