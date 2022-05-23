#!/bin/bash

echo -n abc | gmssl sm3

gmssl sm2keygen -pass 1234 -out sm2.pem -pubout sm2pub.pem
echo -n abc | gmssl sm3 -pubkey sm2pub.pem -id 1234567812345678


echo -n abc | gmssl sm3hmac -key 11223344556677881122334455667788

