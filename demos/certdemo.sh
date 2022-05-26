#!/bin/bash -x

# generate sm2 keypair and encrypt with password
gmssl sm2keygen -pass 1234 -out sm2.pem -pubout sm2pub.pem

# generate a self-signed certificate
gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN Alice -days 365 -key sm2.pem -pass 1234 \
	-key_usage "digitalSignature" -key_usage "keyCertSign" -key_usage cRLSign \
	-out cert.pem

gmssl certparse -in cert.pem



