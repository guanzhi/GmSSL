/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

"Examples\n"
"\n"
"Supported cipher suites:\n"
"      TLS_ECC_SM4_GCM_SM3\n"
"      TLS_ECC_SM4_CBC_SM3\n"
"\n"
"  gmssl tlcp_client -host www.pbc.gov.cn -get / -certout certs.pem\n"
"\n"
"  gmssl tlcp_client -host www.pbc.gov.cn -port 443\n"
"\n"
"Examples\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out rootcakey.pem\n"
"    gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 -key rootcakey.pem -pass 1234 -out rootcacert.pem -key_usage keyCertSign -key_usage cRLSign -ca\n"
"    gmssl sm2keygen -pass 1234 -out cakey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN \"Sub CA\" -key cakey.pem -pass 1234 -out careq.pem\n"
"    gmssl reqsign -in careq.pem -days 365 -key_usage keyCertSign -ca -path_len_constraint 0 -cacert rootcacert.pem -key rootcakey.pem -pass 1234 -out cacert.pem\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out signkey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key signkey.pem -pass 1234 -out signreq.pem\n"
"    gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass 1234 -out signcert.pem\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out enckey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key enckey.pem -pass 1234 -out encreq.pem\n"
"    gmssl reqsign -in encreq.pem -days 365 -key_usage keyEncipherment -cacert cacert.pem -key cakey.pem -pass 1234 -out enccert.pem\n"
"\n"
"    cat signcert.pem > double_certs.pem\n"
"    cat enccert.pem >> double_certs.pem\n"
"    cat cacert.pem >> double_certs.pem\n"
"    # double_keys.pem contains two encrypted private key PEM blocks with the same password:\n"
"    # the first is the signing private key, the second is the encryption private key.\n"
"    cat signkey.pem > double_keys.pem\n"
"    cat enckey.pem >> double_keys.pem\n"
"\n"
"    gmssl tlcp_server -port 443 -cert double_certs.pem -key double_keys.pem -pass 1234\n"
"    gmssl tlcp_client -host 127.0.0.1 -cacert rootcacert.pem\n"
