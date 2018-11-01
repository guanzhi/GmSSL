#!/bin/bash -x
#
# FIXME: if App already exist, this script will fail.
#


VERBOSE=2
SO_PATH="./libsdf.so"
LABEL="MySKF"
APPNAME="MyApp1"
APPNAME2="MyApp2"

echo "[Sign/Verify with SM2 Container]"
echo "abc" | gmssl sm3 -binary | sudo gmssl pkeyutl -sign -pkeyopt ec_scheme:sm2 -engine sdf  -keyform engine -inkey ecc_1.sign -out sm2.sig
echo "abc" | gmssl sm3 -binary | sudo gmssl pkeyutl -verify -pkeyopt ec_scheme:sm2 -engine sdf  -keyform engine -inkey ecc_1.sign -sigfile sm2.sig

echo "[Verify with exported SM2 Verification Public Key]"
sudo gmssl pkey -engine sdf -inform engine -in ecc_1.sign -pubout -out sm2vkey.pem
echo "abc" | gmssl sm3 -binary | gmssl pkeyutl -verify -pkeyopt ec_scheme:sm2 -pubin -inkey sm2vkey.pem -sigfile sm2.sig

