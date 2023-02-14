#!/bin/bash -x

set -e

cd ../certs

gmssl certparse -in "rootca/Civil Servant ROOT.pem"
gmssl certverify -in "rootca/Civil Servant ROOT.pem" -cacert "rootca/Civil Servant ROOT.pem"
gmssl crlparse -in "crl/Civil Servant ROOT.crl"
gmssl crlverify -in "crl/Civil Servant ROOT.crl" -cacert "rootca/Civil Servant ROOT.pem"

gmssl certparse -in "rootca/Device ROOT.pem"
gmssl certverify -in "rootca/Device ROOT.pem" -cacert "rootca/Device ROOT.pem"
gmssl crlparse -in "crl/Device ROOT.crl"
gmssl crlverify -in "crl/Device ROOT.crl" -cacert "rootca/Device ROOT.pem"

gmssl certparse -in "rootca/ROOTCA.pem"
gmssl certverify -in "rootca/ROOTCA.pem" -cacert "rootca/ROOTCA.pem"
gmssl crlparse -in "crl/ROOTCA.crl"
gmssl crlverify -in "crl/ROOTCA.crl" -cacert "rootca/ROOTCA.pem" # now > next_update

# The CRL URI of ROOTCA.pem is in Base64 format, not DER
gmssl certverify -in "ca/TJCA.pem" -cacert "rootca/Civil Servant ROOT.pem" #-check_crl
gmssl certverify -in "ca/Taier CA.pem" -cacert "rootca/ROOTCA.pem" #-check_crl
gmssl certverify -in "ca/Ant Financial Certification Authority S1.pem" -cacert "rootca/ROOTCA.pem" #-check_crl

echo ok
