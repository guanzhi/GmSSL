#!/bin/bash -x

rm -fr *.pem
rm -fr *.der

# generate sm2 keypair and encrypt with password
sm2keygen -pass 123456 -out cakey.pem -pubout capubkey.pem

# generate a self-signed certificate
certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN CA -days 365 -key cakey.pem -pass 123456 -out cacert.pem
certparse -in cacert.pem

# generate a req and sign by ca certificate
sm2keygen -pass 123456 -out key.pem -pubout pubkey.pem
reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN Alice -days 365 -key key.pem -pass 123456 -out req.pem
reqparse -in req.pem
reqsign -in req.pem -days 365 -cacert cacert.pem -key cakey.pem -pass 123456 -out cert.pem
certparse -in cert.pem

# hash and hmac
echo -n "abc" | sm3
echo -n "abc" | sm3hmac -keyhex 1122334455667788

# encrypt with public key
echo hello | sm2encrypt -pubkey pubkey.pem -out ciphertext.der
sm2decrypt -in ciphertext.der -key key.pem -pass 123456

# encrypt with certificate
echo hello | sm2encrypt -cert cert.pem -out ciphertext.der
sm2decrypt -in ciphertext.der -key key.pem -pass 123456

# sign and verify with public key and certificate
echo hello | sm2sign -key key.pem -pass 123456 -out signature.der
echo hello | sm2verify -pubkey pubkey.pem -sig signature.der
echo hello | sm2verify -cert cert.pem -sig signature.der

