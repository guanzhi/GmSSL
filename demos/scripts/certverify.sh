#!/bin/bash -x

set -e

signcert=ebssec.boc.cn-sign.pem
enccert=ebssec.boc.cn-enc.pem
crl=CFCA_SM2_OCA1.crl
cacert=CFCA_SM2_OCA1.pem
rootcacert=CFCA_CS_SM2_CA.pem


cat << EOF > $signcert
-----BEGIN CERTIFICATE-----
MIICzzCCAnKgAwIBAgIFEzY5M3AwDAYIKoEcz1UBg3UFADAlMQswCQYDVQQGEwJD
TjEWMBQGA1UECgwNQ0ZDQSBTTTIgT0NBMTAeFw0yMTA2MTEwOTA1MjBaFw0yNjA2
MTkwODE2NTZaMIGRMQswCQYDVQQGEwJDTjEPMA0GA1UECAwG5YyX5LqsMQ8wDQYD
VQQHDAbljJfkuqwxJzAlBgNVBAoMHuS4reWbvemTtuihjOiCoeS7veaciemZkOWF
rOWPuDERMA8GA1UECwwITG9jYWwgUkExDDAKBgNVBAsMA1NTTDEWMBQGA1UEAwwN
ZWJzc2VjLmJvYy5jbjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABPsNUnoZQM9C
SnvC57TbvdfyOTCuPOSlZmPAyxBKFj+Y1QH/xlubHdVf5XqHrO1jCDRi7aN5IKGX
QF1492c803OjggEeMIIBGjAfBgNVHSMEGDAWgBRck1ggWiRzVhAbZFAQ7OmnygdB
ETAMBgNVHRMBAf8EAjAAMEgGA1UdIARBMD8wPQYIYIEchu8qAQEwMTAvBggrBgEF
BQcCARYjaHR0cDovL3d3dy5jZmNhLmNvbS5jbi91cy91cy0xNC5odG0wNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5jZmNhLmNvbS5jbi9TTTIvY3JsNTYxOC5j
cmwwGAYDVR0RBBEwD4INZWJzc2VjLmJvYy5jbjAOBgNVHQ8BAf8EBAMCBsAwHQYD
VR0OBBYEFJ6oFo/OrKgDhHFORpaq04kX7T1KMB0GA1UdJQQWMBQGCCsGAQUFBwMC
BggrBgEFBQcDATAMBggqgRzPVQGDdQUAA0kAMEYCIQCvhSvbv5h6ERl1YcCLg+fz
9UleQbaPfBYwUjUD2dAHVQIhAMRC4k9S/mSC0UpUvCqh/DQC2Ui8Tccd5G2IgYSs
cnUN
-----END CERTIFICATE-----
EOF

cat << EOF > $enccert
-----BEGIN CERTIFICATE-----
MIICzjCCAnKgAwIBAgIFEzY5M3EwDAYIKoEcz1UBg3UFADAlMQswCQYDVQQGEwJD
TjEWMBQGA1UECgwNQ0ZDQSBTTTIgT0NBMTAeFw0yMTA2MTEwOTA1MjBaFw0yNjA2
MTkwODE2NTZaMIGRMQswCQYDVQQGEwJDTjEPMA0GA1UECAwG5YyX5LqsMQ8wDQYD
VQQHDAbljJfkuqwxJzAlBgNVBAoMHuS4reWbvemTtuihjOiCoeS7veaciemZkOWF
rOWPuDERMA8GA1UECwwITG9jYWwgUkExDDAKBgNVBAsMA1NTTDEWMBQGA1UEAwwN
ZWJzc2VjLmJvYy5jbjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABMn1q+hbV0i1
qnKAy7QeZ3ZfAD+gqHX4F5MqIhsarODlWsavf/dcprC0F277zc44aYBB/3ucy4PF
qXaRHQp8PEyjggEeMIIBGjAfBgNVHSMEGDAWgBRck1ggWiRzVhAbZFAQ7OmnygdB
ETAMBgNVHRMBAf8EAjAAMEgGA1UdIARBMD8wPQYIYIEchu8qAQEwMTAvBggrBgEF
BQcCARYjaHR0cDovL3d3dy5jZmNhLmNvbS5jbi91cy91cy0xNC5odG0wNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5jZmNhLmNvbS5jbi9TTTIvY3JsNTYxOC5j
cmwwGAYDVR0RBBEwD4INZWJzc2VjLmJvYy5jbjAOBgNVHQ8BAf8EBAMCAzgwHQYD
VR0OBBYEFF/a1JHvzLzbpFbBljX7hNxRpj/2MB0GA1UdJQQWMBQGCCsGAQUFBwMC
BggrBgEFBQcDATAMBggqgRzPVQGDdQUAA0gAMEUCIQDCOFi1eZcgiN6t+h6lxLwS
grAh3Jall+ZyA2ePw6xcjwIgNyDvo761dpwJhcyWfyVCAnaTf0Vf4DLWI1K+S7po
Ur8=
-----END CERTIFICATE-----
EOF


cat << EOF > $cacert
-----BEGIN CERTIFICATE-----
MIICNTCCAdmgAwIBAgIFEAAAAAgwDAYIKoEcz1UBg3UFADBYMQswCQYDVQQGEwJD
TjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9y
aXR5MRcwFQYDVQQDDA5DRkNBIENTIFNNMiBDQTAeFw0xMzAxMjQwODQ2NDBaFw0z
MzAxMTkwODQ2NDBaMCUxCzAJBgNVBAYTAkNOMRYwFAYDVQQKDA1DRkNBIFNNMiBP
Q0ExMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEfJqQoo0+JoyCRy0msS2Ym076
8nV1pSLuK9utS1ij38obWDymq0oMRRwUzDMEQI19Cajo3JUoGFxOvsA+YWu3XKOB
wDCBvTAfBgNVHSMEGDAWgBTkjt3Uo+e2D+4dJ5bNddwlJXJp3TAMBgNVHRMEBTAD
AQH/MGAGA1UdHwRZMFcwVaBToFGkTzBNMQswCQYDVQQGEwJDTjETMBEGA1UECgwK
Q0ZDQSBDUyBDQTEMMAoGA1UECwwDQ1JMMQwwCgYDVQQLDANTTTIxDTALBgNVBAMM
BGNybDEwCwYDVR0PBAQDAgEGMB0GA1UdDgQWBBRck1ggWiRzVhAbZFAQ7OmnygdB
ETAMBggqgRzPVQGDdQUAA0gAMEUCIBVscoZJhUy4eToK4C//LjvhjKK2qpBFac/h
Pr6yYTLzAiEAiyqrqsGUU5vGkDo5bEpmF1EbnY8xovsM9vCx98yBrVM=
-----END CERTIFICATE-----
EOF


cat << EOF > $rootcacert
-----BEGIN CERTIFICATE-----
MIICAzCCAaegAwIBAgIEFy9CWTAMBggqgRzPVQGDdQUAMFgxCzAJBgNVBAYTAkNO
MTAwLgYDVQQKDCdDaGluYSBGaW5hbmNpYWwgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
dHkxFzAVBgNVBAMMDkNGQ0EgQ1MgU00yIENBMB4XDTEyMDgzMTAyMDY1OVoXDTQy
MDgyNDAyMDY1OVowWDELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFu
Y2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEXMBUGA1UEAwwOQ0ZDQSBDUyBT
TTIgQ0EwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATuRh26wmtyKNMz+Pmneo3a
Sme+BCjRon8SvAxZBgLSuIxNUewq4kNujeb1I4A0yg7xNcjuOgXglAoQv+Tc+P0V
o10wWzAfBgNVHSMEGDAWgBTkjt3Uo+e2D+4dJ5bNddwlJXJp3TAMBgNVHRMEBTAD
AQH/MAsGA1UdDwQEAwIBBjAdBgNVHQ4EFgQU5I7d1KPntg/uHSeWzXXcJSVyad0w
DAYIKoEcz1UBg3UFAANIADBFAiBhP/rmIvles3RK1FfcmmEeS9RZdu+5lCzxF0nk
cof2QAIhAPVRpqOuceEQHsR77FBe/DgVPqF6lOyoZs0TzTDHrN8c
-----END CERTIFICATE-----
EOF

gmssl certverify -in $signcert -cacert $cacert
gmssl certverify -in $enccert -cacert $cacert
gmssl certverify -in $cacert -cacert $rootcacert

chain=chain.pem
cat $signcert > $chain
cat $cacert >> $chain
gmssl certverify -in $chain -cacert $rootcacert

chain_with_root=chain_with_root.pem
cp $chain $chain_with_root
cat $rootcacert >> $chain_with_root
gmssl certverify -in $chain_with_root -cacert $rootcacert

double_certs=double_certs.pem
cat $signcert > $double_certs
cat $enccert >> $double_certs
gmssl certverify -in $double_certs -cacert $cacert -double_certs

double_chain=double_chain.pem
cat $double_certs > $double_chain
cat $cacert >> $double_chain
gmssl certverify -in $double_chain -cacert $rootcacert -double_certs

gmssl certparse -in $double_chain
gmssl certverify -in $double_chain -cacert $rootcacert -double_certs -check_crl
gmssl crlget -cert $signcert -out $crl
gmssl crlparse -in $crl

rm -fr $signcert
rm -fr $enccert
rm -fr $crl
rm -fr $cacert
rm -fr $rootcacert
rm -fr $chain
rm -fr $chain_with_root
rm -fr $double_certs
rm -fr $double_chain

echo ok

