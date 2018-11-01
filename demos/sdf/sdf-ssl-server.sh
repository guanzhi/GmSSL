#!/bin/bash
# `-trace` option require `.config enable-ssl-trace`

#trace="-trace"

#sudo gmssl s_server -tls1_2 -unlink -port 443 -cipher SM2 -engine sdf -keyform ENGINE -key ecc_1.sign -cert localhost-signcer.pem  -msg -rev 
sudo gmssl s_server -rev $trace -tls1_2 -unlink -port 4433 -cipher SM2  -engine sdf -keyform ENGINE -cert localhost.pem -key ecc_1.sign
