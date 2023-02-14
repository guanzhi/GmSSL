#!/bin/bash -x

set -e

gmssl sm2keygen -pass 1234 -out rootcakey.pem
gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 -key rootcakey.pem -pass 1234 -out rootcacert.pem -key_usage keyCertSign -key_usage cRLSign
gmssl certparse -in rootcacert.pem

gmssl sm2keygen -pass 1234 -out cakey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN "Sub CA" -key cakey.pem -pass 1234 -out careq.pem
gmssl reqsign -in careq.pem -days 365 -key_usage keyCertSign -path_len_constraint 0 -cacert rootcacert.pem -key rootcakey.pem -pass 1234 -out cacert.pem
gmssl certparse -in cacert.pem

gmssl sm2keygen -pass 1234 -out signkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key signkey.pem -pass 1234 -out signreq.pem
gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out signcert.pem
gmssl certparse -in signcert.pem

gmssl sm2keygen -pass 1234 -out enckey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key enckey.pem -pass 1234 -out encreq.pem
gmssl reqsign -in encreq.pem -days 365 -key_usage keyEncipherment -cacert cacert.pem -key cakey.pem -pass 1234 -out enccert.pem
gmssl certparse -in enccert.pem

rm -fr revoked_certs.der
gmssl certrevoke -in signcert.pem -reason keyCompromise -out revoked_certs.der
gmssl certrevoke -in enccert.pem -reason keyCompromise -out revoked_certs.der
gmssl crlgen -in revoked_certs.der -cacert cacert.pem -key cakey.pem -pass 1234 -next_update 20240101000000Z -gen_authority_key_id -crl_num 1 -out crl.der
gmssl crlparse -in crl.der

rm -fr rootcakey.pem
rm -fr rootcacert.pem
rm -fr cakey.pem
rm -fr careq.pem
rm -fr cacert.pem
rm -fr signkey.pem
rm -fr signreq.pem
rm -fr signcert.pem
rm -fr enckey.pem
rm -fr encreq.pem
rm -fr enccert.pem
rm -fr revoked_certs.der
rm -fr crl.der

echo "all ok"
