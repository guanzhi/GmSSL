#!/bin/bash


ENC_KEY=`gmssl rand -outlen 16 -hex`
MAC_KEY=`gmssl rand -outlen 32 -hex`
IV=`gmssl rand -outlen 16 -hex`

gmssl sm2keygen -pass 1234 -out sm2.pem -pubout sm2pub.pem

echo "$ENC_KEY$MAC_KEY" | xxd -p -r |  gmssl sm2encrypt -pubkey sm2pub.pem | xxd -p > out.bin
echo $IV >> out.bin
echo "plaintext" | gmssl sm4 -cbc -encrypt -key $ENC_KEY -iv $IV | xxd -p >> out.bin


# gmssl sm2decrypt -key sm2.pem -pass 1234 -in sm2.der

