/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

"\n"
"Supported cipher suites:\n"
"      TLS_ECC_SM4_GCM_SM3\n"
"      TLS_ECC_SM4_CBC_SM3\n"
"\n"
"\n"
"Examples\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out sm2rootcakey.pem\n"
"    gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 -key sm2rootcakey.pem -pass 1234 -out sm2rootcacert.pem -key_usage keyCertSign -key_usage cRLSign -ca\n"
"    gmssl sm2keygen -pass 1234 -out sm2cakey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN \"Sub CA\" -key sm2cakey.pem -pass 1234 -out sm2careq.pem\n"
"    gmssl reqsign -in sm2careq.pem -days 365 -key_usage keyCertSign -ca -path_len_constraint 0 -cacert sm2rootcacert.pem -key sm2rootcakey.pem -pass 1234 -out sm2cacert.pem\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out sm2signkey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key sm2signkey.pem -pass 1234 -out sm2signreq.pem\n"
"    gmssl reqsign -in sm2signreq.pem -days 365 -key_usage digitalSignature -cacert sm2cacert.pem -key sm2cakey.pem -pass 1234 -out sm2signcert.pem\n"
"\n"
"    gmssl sm2keygen -pass 1234 -out sm2enckey.pem\n"
"    gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key sm2enckey.pem -pass 1234 -out sm2encreq.pem\n"
"    gmssl reqsign -in sm2encreq.pem -days 365 -key_usage keyEncipherment -cacert sm2cacert.pem -key sm2cakey.pem -pass 1234 -out sm2enccert.pem\n"
"\n"
"    cat sm2signcert.pem > tlcpcert.pem\n"
"    cat sm2enccert.pem >> tlcpcert.pem\n"
"    cat sm2cacert.pem >> tlcpcert.pem\n"
"    cat sm2signkey.pem > tlcpkey.pem\n"
"    cat sm2enckey.pem >> tlcpkey.pem\n"
"\n"
"    gmssl tlcp_server -port 4431 -cert tlcpcert.pem -key tlcpkey.pem -pass 1234 -cipher_suite TLS_ECC_SM4_CBC_SM3\n"
"    gmssl tlcp_client -port 4431 -host 127.0.0.1 -cacert sm2rootcacert.pem -cipher_suite TLS_ECC_SM4_CBC_SM3\n"
