#!/bin/bash -x

gmca=./gmca

echo "Generate self-signed root CA certificate, configurations and database"
$gmca -setup

echo "Get root CA certificate"
$gmca -cacert

echo "Generate CSR for Alice, Bob and Carol"
$gmca -gencsr alice@pku.edu.cn
$gmca -gencsr bob@pku.edu.cn
$gmca -gencsr carol@pku.edu.cn

echo "CA sign CSRs"
$gmca -listcsrs
$gmca -showcsr alice@pku.edu.cn
$gmca -signcsr alice@pku.edu.cn
$gmca -signcsr bob@pku.edu.cn

echo "Reject some CSRs"
$gmca -rejectcsr carol@pku.edu.cn
$gmca -listcsrs

echo "List all certificates"
$gmca -listcerts

echo "Search certificate with CommonName"
$gmca -listcertsbyname alice

echo "Get certificate with CommonName"
$gmca -getcertbyname alice

echo "Get certificate with Serial Number"
$gmca -getcertbyserial 01

#echo "Write certificate to SKF device"

echo "Revoke certificate with Serial Number"
$gmca -revokecertbyserial 01

echo "Generate CRL"
$gmca -gencrl

echo "Show CRL"
$gmca -showcrl

echo "Get CRL"
$gmca -getcrl

echo "Backup"
$gmca -backup

