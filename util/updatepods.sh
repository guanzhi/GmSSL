#!/bin/sh
#
# This script replace the "openssl" command name string to "gmssl" of the pod
# files in current folder (normally doc/apps/).

mv openssl.pod gmssl.pod
sed -i "" 's/openssl/gmssl/g' *.pod
sed -i "" 's/gmssl.cnf/openssl.cnf/g' *.pod
sed -i "" 's/www.gmssl.org/www.openssl.org/g' *.pod
sed -i "" 's/OpenSSL/GmSSL/g' *.pod
sed -i "" 's/GmSSL Project Authors/OpenSSL Project Authors/g' *.pod
sed -i "" 's/EC/EC\/SM2/g' gmssl.pod
sed -i "" 's/md2/sm3/g' gmssl.pod
sed -i "" 's/MD2/SM3/g' gmssl.pod
sed -i "" 's/bf/sms4/g' gmssl.pod
sed -i "" 's/Blowfish/SMS4/g' gmssl.pod
sed -i "" 's/secp192v1/sm2p256v1/g' ecparam.pod
sed -i "" 's/sha256/sm3/g' dgst.pod
sed -i "" 's/SHA256/SM3/g' dgst.pod
sed -i "" 's/1.1.0/2.0/g' dgst.pod
sed -i "" 's/sha-256/SM3/g' enc.pod
sed -i "" 's/idea/sms4/g' ec.pod
sed -i "" 's/IDEA/SMS4/g' ec.pod
