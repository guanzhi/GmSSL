#!/bin/bash -x


gmssl sm2keygen -pass 1234 -out rootcakey.pem
gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 -key rootcakey.pem -pass 1234 -out rootcacert.pem -key_usage keyCertSign -key_usage cRLSign -ca
gmssl certparse -in rootcacert.pem

gmssl sm2keygen -pass 1234 -out cakey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN "Sub CA" -key cakey.pem -pass 1234 -out careq.pem
gmssl reqsign -in careq.pem -days 365 -key_usage keyCertSign -ca -path_len_constraint 0 -cacert rootcacert.pem -key rootcakey.pem -pass 1234 -out cacert.pem
gmssl certparse -in cacert.pem

gmssl sm2keygen -pass 1234 -out signkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key signkey.pem -pass 1234 -out signreq.pem
gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out signcert.pem
gmssl certparse -in signcert.pem

cat signcert.pem > certs.pem
cat cacert.pem >> certs.pem

# If port is already in use, `gmssl` will fail, use `ps aux | grep gmssl` and `sudo kill -9` to kill existing proc
# TODO: check if `gmssl` is failed
which sudo
if [ $? -eq 0 ]; then
	SUDO=sudo
fi
$SUDO gmssl tls13_server -port 4433 -cert certs.pem -key signkey.pem -pass 1234 -cacert cacert.pem & # 1>/dev/null  2>/dev/null &
sleep 3

gmssl sm2keygen -pass 1234 -out clientkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN Client -key clientkey.pem -pass 1234 -out clientreq.pem
gmssl reqsign -in clientreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out clientcert.pem
gmssl certparse -in clientcert.pem

gmssl tls13_client -host 127.0.0.1 -port 4433 -cacert rootcacert.pem -cert clientcert.pem -key clientkey.pem -pass 1234

