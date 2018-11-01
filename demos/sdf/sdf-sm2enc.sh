#!/bin/bash -x

echo "######################################################################"
echo "#                                                                    #"
echo "#                Default PIN:  11111111                              #"
echo "#                                                                    #"
echo "######################################################################"

echo "secret" | \
  sudo gmssl pkeyutl -encrypt -engine sdf -keyform engine -inkey ecc_1.exch -out sm2ciphertext.der

# export the public key of the default encrypt/keyexchagne SM2 private key
# the default ID of the key container is `ecc_1.exch`
sudo gmssl pkey -engine sdf -inform engine -in ecc_1.exch -pubout -out sm2enckey.pem

echo "secret" | \
  gmssl pkeyutl -encrypt -pkeyopt ec_scheme:sm2 -pkeyopt ec_encrypt_param:sm3 -pubin -inkey sm2enckey.pem -out sm2ciphertext2.der

sudo gmssl pkeyutl -decrypt -engine sdf -keyform engine -inkey ecc_1.exch -in sm2ciphertext.der
sudo gmssl pkeyutl -decrypt -engine sdf -keyform engine -inkey ecc_1.exch -in sm2ciphertext2.der

