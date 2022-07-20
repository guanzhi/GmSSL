#!/bin/bash -x


# server-authentication only
../build/bin/tls12_server -cert cert.pem -key key.pem -pass 123456  1>/dev/null  2>/dev/null &
sleep 3
../build/bin/tls12_client -host 127.0.0.1 -cacert cacert.pem


# mutual authentication, i.e. client certificate requested
../build/bin/tls12_server -cert cert.pem -key key.pem -pass 123456 -cacert cacert.pem 1>/dev/null  2>/dev/null &
sleep 3
../build/bin/tls12_client -host 127.0.0.1 -cacert cacert.pem -cert cert.pem -key key.pem -pass 123456


