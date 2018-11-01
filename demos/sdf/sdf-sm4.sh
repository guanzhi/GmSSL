#!/bin/bash -x

#key=00000000000000000000000000000000
#iv=00000000000000000000000000000000

key=12345678123456781234567812345678
iv=12345678123456781234567812345678
plaintext="This is the plaintext message."

ciphertext=`echo $plaintext | sudo gmssl sms4 -K $key -iv $iv -a`

echo $ciphertext
echo $plaintext | sudo gmssl sms4 -engine sdf -K $key -iv $iv -a
echo $ciphertext | sudo gmssl sms4 -d -engine sdf -K $key -iv $iv -a
