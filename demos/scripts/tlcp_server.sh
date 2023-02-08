#!/bin/bash -x


gmssl sm2keygen -pass 1234 -out rootcakey.pem
gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 -key rootcakey.pem -pass 1234 -out rootcacert.pem -key_usage keyCertSign -key_usage cRLSign -ca
gmssl certparse -in rootcacert.pem

gmssl sm2keygen -pass 1234 -out cakey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN "Sub CA" -key cakey.pem -pass 1234 -out careq.pem
gmssl reqsign -in careq.pem -days 365 -key_usage keyCertSign -path_len_constraint 0 -cacert rootcacert.pem -key rootcakey.pem -pass 1234 -out cacert.pem -ca
gmssl certparse -in cacert.pem

gmssl sm2keygen -pass 1234 -out signkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key signkey.pem -pass 1234 -out signreq.pem
gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out signcert.pem
gmssl certparse -in signcert.pem

gmssl sm2keygen -pass 1234 -out enckey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key enckey.pem -pass 1234 -out encreq.pem
gmssl reqsign -in encreq.pem -days 365 -key_usage keyEncipherment -cacert cacert.pem -key cakey.pem -pass 1234 -out enccert.pem
gmssl certparse -in enccert.pem

cat signcert.pem > double_certs.pem
cat enccert.pem >> double_certs.pem
cat cacert.pem >> double_certs.pem

sudo gmssl tlcp_server -port 443 -cert double_certs.pem -key signkey.pem -pass 1234 -ex_key enckey.pem -ex_pass 1234 -cacert cacert.pem  1>/dev/null  2>/dev/null &
#sudo gmssl tlcp_server -port 443 -cert double_certs.pem -key signkey.pem -pass 1234 -ex_key enckey.pem -ex_pass 1234  1>/dev/null  2>/dev/null &
sleep 3

gmssl sm2keygen -pass 1234 -out clientkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN Client -key clientkey.pem -pass 1234 -out clientreq.pem
gmssl reqsign -in clientreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out clientcert.pem
gmssl certparse -in clientcert.pem

# build and install BabaSSL 8.3.2
# Download
# ./config enable-ntls; make; sudo make install

# current /demos/scripts
#  /build/bin

openssl version

../../build/bin/demo_sm2_key_export clientkey.pem 1234 > clientpkey.pem

#openssl s_client -enable_ntls -ntls -connect localhost:443 -no_ticket -CAfile rootcacert.pem -sign_cert clientcert.pem -sign_key clientpkey.pem -pass pass:1234


