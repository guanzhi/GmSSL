#!/bin/bash -x

set -e

gmssl sm2keygen -pass 1234 -out rootcakey.pem
gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 \
	-key rootcakey.pem -pass 1234 \
	-out rootcacert.pem \
	-ca -path_len_constraint 6 \
	-key_usage keyCertSign -key_usage cRLSign \
	-crl_http_uri http://pku.edu.cn/ca.crl -ca_issuers_uri http://pku.edu.cn/ca.crt -ocsp_uri http://ocsp.pku.edu.cn

gmssl certparse -in rootcacert.pem

gmssl sm2keygen -pass 1234 -out cakey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN "Sub CA" -key cakey.pem -pass 1234 -out careq.pem
gmssl reqsign -in careq.pem -days 365 -key_usage keyCertSign -path_len_constraint 0 -cacert rootcacert.pem -key rootcakey.pem -pass 1234 -out cacert.pem \
	-crl_http_uri http://pku.edu.cn/ca.crl -ca_issuers_uri http://pku.edu.cn/ca.crt -ocsp_uri http://ocsp.pku.edu.cn
gmssl certparse -in cacert.pem

gmssl sm2keygen -pass 1234 -out signkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key signkey.pem -pass 1234 -out signreq.pem
gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out signcert.pem \
	-crl_http_uri http://github.com/guanzhi/GmSSL/raw/master/demos/certs/SubCA-1.crl
gmssl certparse -in signcert.pem

gmssl sm2keygen -pass 1234 -out enckey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key enckey.pem -pass 1234 -out encreq.pem
gmssl reqsign -in encreq.pem -days 365 -key_usage keyEncipherment -cacert cacert.pem -key cakey.pem -pass 1234 -out enccert.pem \
	-crl_http_uri http://github.com/guanzhi/GmSSL/raw/master/demos/certs/SubCA-1.crl
gmssl certparse -in enccert.pem

cat signcert.pem > certs.pem
cat cacert.pem >> certs.pem
gmssl certverify -in certs.pem -cacert rootcacert.pem #-check_crl

cat signcert.pem > dbl_certs.pem
cat enccert.pem >> dbl_certs.pem
cat cacert.pem >> dbl_certs.pem
gmssl certverify -double_certs -in dbl_certs.pem -cacert rootcacert.pem #-check_crl

echo ok

