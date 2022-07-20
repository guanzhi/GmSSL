#!/bin/bash


gmssl sm2keygen -pass 1234 -out cakey.pem
gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN CA -days 365 -key cakey.pem -pass 1234 -out cacert.pem -key_usage keyCertSign -key_usage cRLSign
gmssl certparse -in cacert.pem

gmssl sm2keygen -pass 1234 -out signkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -days 365 -key signkey.pem -pass 1234 -out signreq.pem
gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out signcert.pem
gmssl certparse -in signcert.pem

gmssl sm2keygen -pass 1234 -out enckey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -days 365 -key enckey.pem -pass 1234 -out encreq.pem
gmssl reqsign -in encreq.pem -days 365 -key_usage keyEncipherment -cacert cacert.pem -key cakey.pem -pass 1234 -out enccert.pem
gmssl certparse -in enccert.pem

cat signcert.pem > cert.pem
cat enccert.pem >> cert.pem

sudo gmssl tlcp_server -cert cert.pem -key signkey.pem -pass 1234 -ex_key enckey.pem -ex_pass 1234 # -cacert cacert.pem

