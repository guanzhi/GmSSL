#!/bin/bash -x

set -e

# generate self-signed CA certificate
gmssl sm2keygen -pass 1234 -out cakey.pem -pubout pubkey.pem
gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN CA -days 365 -key cakey.pem -pass 1234 -out cacert.pem
gmssl certparse -in cacert.pem

# generate a req and sign by CA certificate
gmssl sm2keygen -pass 1234 -out signkey.pem -pubout pubkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN Alice -key signkey.pem -pass 1234 -out signreq.pem
gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out signcert.pem
gmssl certparse -in signcert.pem

# sign a encryption certificate with the same DN, different KeyUsage extension
gmssl sm2keygen -pass 1234 -out enckey.pem -pubout pubkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN Alice -key enckey.pem -pass 1234 -out encreq.pem
gmssl reqsign -in encreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out enccert.pem
gmssl certparse -in enccert.pem

# 中文
gmssl sm2keygen -pass 1234 -out alicekey.pem -pubout alicepubkey.pem
gmssl reqgen -O "北京大学" -CN "爱丽丝" -key alicekey.pem -pass 1234 -out alicereq.pem
gmssl reqsign -in alicereq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out alicecert.pem
gmssl certparse -in alicecert.pem


rm -fr pubkey.pem
rm -fr cacert.pem
rm -fr signkey.pem
rm -fr signreq.pem
rm -fr signcert.pem
rm -fr enckey.pem
rm -fr encreq.pem
rm -fr enccert.pem
rm -fr alicekey.pem
rm -fr alicepubkey.pem
rm -fr alicereq.pem
rm -fr alicecert.pem

echo ok
