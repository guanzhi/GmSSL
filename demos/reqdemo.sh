#!/bin/bash -x

# generate self-signed CA certificate
gmssl sm2keygen -pass 1234 -out cakey.pem -pubout pubkey.pem
gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN CA -days 365 -key cakey.pem -pass 1234 -out cacert.pem
gmssl certparse -in cacert.pem

# generate a req and sign by CA certificate
gmssl sm2keygen -pass 1234 -out signkey.pem -pubout pubkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN Alice -days 365 -key signkey.pem -pass 1234 -out signreq.pem
gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out signcert.pem
gmssl certparse -in signcert.pem

# sign a encryption certificate with the same DN, different KeyUsage extension
gmssl sm2keygen -pass 1234 -out enckey.pem -pubout pubkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN Alice -days 365 -key enckey.pem -pass 1234 -out encreq.pem
gmssl reqsign -in encreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out enccert.pem
gmssl certparse -in enccert.pem

