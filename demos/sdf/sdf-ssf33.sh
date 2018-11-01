#!/bin/bash -x

#key=00000000000000000000000000000000
#iv=00000000000000000000000000000000

key=12345678123456781234567812345678
iv=12345678123456781234567812345678
plaintext="This is the plaintext message."

# FIXME: sm1/ssf33 is unkonwn to enc command
ciphertext=`echo $plaintext | sudo gmssl enc -sm1 -engine sdf -K $key -iv $iv -a`
plaintext=`echo $ciphertext | sudo gmssl enc -sm1 -d -engine sdf -K $key -iv $iv -a`

echo "Ciphertext: $ciphertext"
echo "Plaintext: $plaintext"

