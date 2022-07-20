#!/bin/bash


# 当服务器发送CertificateRequest而Client又没有用证书、密钥时，会SegFault


#../build/bin/tls12_client -host 127.0.0.1 -cacert cacert.pem -cert cert.pem -key key.pem -pass 123456
../build/bin/tlcp_client -host 127.0.0.1 -cacert cacert.pem # -cert cert.pem -key key.pem -pass 123456


