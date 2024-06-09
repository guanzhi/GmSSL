/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>


extern int version_main(int argc, char **argv);
extern int rand_main(int argc, char **argv);
extern int certgen_main(int argc, char **argv);
extern int certparse_main(int argc, char **argv);
extern int certverify_main(int argc, char **argv);
extern int certrevoke_main(int argc, char **argv);
extern int crlget_main(int argc, char **argv);
extern int crlgen_main(int argc, char **argv);
extern int crlparse_main(int argc, char **argv);
extern int crlverify_main(int argc, char **argv);
extern int reqgen_main(int argc, char **argv);
extern int reqparse_main(int argc, char **argv);
extern int reqsign_main(int argc, char **argv);
extern int sm2keygen_main(int argc, char **argv);
extern int sm2sign_main(int argc, char **argv);
extern int sm2verify_main(int argc, char **argv);
extern int sm2encrypt_main(int argc, char **argv);
extern int sm2decrypt_main(int argc, char **argv);
extern int sm3_main(int argc, char **argv);
extern int sm3hmac_main(int argc, char **argv);
extern int sm3_pbkdf2_main(int argc, char **argv);
extern int sm3xmss_keygen_main(int argc, char **argv);
extern int sm4_ecb_main(int argc, char **argv);
extern int sm4_cbc_main(int argc, char **argv);
extern int sm4_ctr_main(int argc, char **argv);
extern int sm4_cfb_main(int argc, char **argv);
extern int sm4_ofb_main(int argc, char **argv);
extern int sm4_ccm_main(int argc, char **argv);
extern int sm4_gcm_main(int argc, char **argv);
extern int sm4_xts_main(int argc, char **argv);
extern int sm4_cbc_sm3_hmac_main(int argc, char **argv);
extern int sm4_ctr_sm3_hmac_main(int argc, char **argv);
extern int sm4_cbc_mac_main(int argc, char **argv);
extern int zuc_main(int argc, char **argv);
extern int ghash_main(int argc, char **argv);
extern int sm9setup_main(int argc, char **argv);
extern int sm9keygen_main(int argc, char **argv);
extern int sm9sign_main(int argc, char **argv);
extern int sm9verify_main(int argc, char **argv);
extern int sm9encrypt_main(int argc, char **argv);
extern int sm9decrypt_main(int argc, char **argv);
extern int cmsparse_main(int argc, char **argv);
extern int cmsencrypt_main(int argc, char **argv);
extern int cmsdecrypt_main(int argc, char **argv);
extern int cmssign_main(int argc, char **argv);
extern int cmsverify_main(int argc, char **argv);
extern int tlcp_client_main(int argc, char **argv);
extern int tlcp_server_main(int argc, char **argv);
extern int tls12_client_main(int argc, char **argv);
extern int tls12_server_main(int argc, char **argv);
extern int tls13_client_main(int argc, char **argv);
extern int tls13_server_main(int argc, char **argv);
#ifdef ENABLE_SDF
extern int sdfinfo_main(int argc, char **argv);
extern int sdfdigest_main(int argc, char **argv);
extern int sdfexport_main(int argc, char **argv);
extern int sdfsign_main(int argc, char **argv);
extern int sdfencrypt_main(int argc, char **argv);
extern int sdfdecrypt_main(int argc, char **argv);
extern int sdftest_main(int argc, char **argv);
#endif
#ifdef ENABLE_SKF
extern int skfutil_main(int argc, char **argv);
#endif

static const char *options =
	"command [options]\n"
	"command -help\n"
	"\n"
	"Commands:\n"
	"  help              Print this help message\n"
	"  version           Print version\n"
	"  rand              Generate random bytes\n"
	"  sm2keygen         Generate SM2 keypair\n"
	"  sm2sign           Generate SM2 signature\n"
	"  sm2verify         Verify SM2 signature\n"
	"  sm2encrypt        Encrypt with SM2 public key\n"
	"  sm2decrypt        Decrypt with SM2 private key\n"
	"  sm3               Generate SM3 hash\n"
	"  sm3hmac           Generate SM3 HMAC tag\n"
	"  sm3_pbkdf2        Hash password into key using PBKDF2 algoritm\n"
	"  sm3xmss_keygen    Generate SM3-XMSS keypair\n"
	"  sm4_ecb           Encrypt or decrypt with SM4 ECB\n"
	"  sm4_cbc           Encrypt or decrypt with SM4 CBC\n"
	"  sm4_ctr           Encrypt or decrypt with SM4 CTR\n"
	"  sm4_cfb           Encrypt or decrypt with SM4 CFB\n"
	"  sm4_ofb           Encrypt or decrypt with SM4 OFB\n"
	"  sm4_ccm           Encrypt or decrypt with SM4 CCM\n"
	"  sm4_gcm           Encrypt or decrypt with SM4 GCM\n"
	"  sm4_xts           Encrypt or decrypt with SM4 XTS\n"
	"  sm4_cbc_sm3_hmac  Encrypt or decrypt with SM4 CBC with SM3-HMAC\n"
	"  sm4_ctr_sm3_hmac  Encrypt or decrypt with SM4 CTR with SM3-HMAC\n"
	"  sm4_cbc_mac       Generate SM4 CBC-MAC\n"
	"  ghash             Generate GHASH\n"
	"  zuc               Encrypt or decrypt with ZUC\n"
	"  sm9setup          Generate SM9 master secret\n"
	"  sm9keygen         Generate SM9 private key\n"
	"  sm9sign           Generate SM9 signature\n"
	"  sm9verify         Verify SM9 signature\n"
	"  sm9encrypt        SM9 public key encryption\n"
	"  sm9decrypt        SM9 decryption\n"
	"  reqgen            Generate certificate signing request (CSR)\n"
	"  reqsign           Generate certificate from CSR\n"
	"  reqparse          Parse and print a CSR\n"
	"  crlget            Download the CRL of given certificate\n"
	"  crlgen            Sign a CRL with CA certificate and private key\n"
	"  crlverify         Verify a CRL with issuer's certificate\n"
	"  crlparse          Parse and print CRL\n"
	"  certgen           Generate a self-signed certificate\n"
	"  certparse         Parse and print certificates\n"
	"  certverify        Verify certificate chain\n"
	"  certrevoke        Revoke certificate and output RevokedCertificate record\n"
	"  cmsparse          Parse CMS (cryptographic message syntax) file\n"
	"  cmsencrypt        Generate CMS EnvelopedData\n"
	"  cmsdecrypt        Decrypt CMS EnvelopedData\n"
	"  cmssign           Generate CMS SignedData\n"
	"  cmsverify         Verify CMS SignedData\n"
#ifdef ENABLE_SDF
	"  sdfinfo           Print SDF device info\n"
	"  sdfdigest         Generate SM3 hash with SDF device\n"
	"  sdfexport         Export SM2 signing public key from SDF device\n"
	"  sdfsign           Generate SM2 signature with SDF internal private key\n"
	"  sdfencrypt        SM2/SM4-CBC hybrid encryption with SDF device\n"
	"  sdfdecrypt        SM2/SM4-CBC hybrid decryption with SDF device\n"
	"  sdftest           Test vendor's SDF library and device\n"
#endif
#ifdef ENABLE_SKF
	"  skfutil           SKF crypto device utility\n"
#endif
	"  tlcp_client       TLCP client\n"
	"  tlcp_server       TLCP server\n"
	"  tls12_client      TLS 1.2 client\n"
	"  tls12_server      TLS 1.2 server\n"
	"  tls13_client      TLS 1.3 client\n"
	"  tls13_server      TLS 1.3 server\n"
	"\n"
	"run `gmssl <command> -help` to print help of the given command\n"
	"\n";


int main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];

	argc--;
	argv++;

	if (argc < 1) {
		printf("Usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "help")) {
			printf("usage: %s %s\n", prog, options);
			return 0;
		} else if (!strcmp(*argv, "version")) {
			return version_main(argc, argv);
		} else if (!strcmp(*argv, "rand")) {
			return rand_main(argc, argv);
		} else if (!strcmp(*argv, "certgen")) {
			return certgen_main(argc, argv);
		} else if (!strcmp(*argv, "certparse")) {
			return certparse_main(argc, argv);
		} else if (!strcmp(*argv, "certverify")) {
			return certverify_main(argc, argv);
		} else if (!strcmp(*argv, "certrevoke")) {
			return certrevoke_main(argc, argv);
		} else if (!strcmp(*argv, "crlget")) {
			return crlget_main(argc, argv);
		} else if (!strcmp(*argv, "crlgen")) {
			return crlgen_main(argc, argv);
		} else if (!strcmp(*argv, "crlparse")) {
			return crlparse_main(argc, argv);
		} else if (!strcmp(*argv, "crlverify")) {
			return crlverify_main(argc, argv);
		} else if (!strcmp(*argv, "reqgen")) {
			return reqgen_main(argc, argv);
		} else if (!strcmp(*argv, "reqparse")) {
			return reqparse_main(argc, argv);
		} else if (!strcmp(*argv, "reqsign")) {
			return reqsign_main(argc, argv);
		} else if (!strcmp(*argv, "sm2keygen")) {
			return sm2keygen_main(argc, argv);
		} else if (!strcmp(*argv, "sm2sign")) {
			return sm2sign_main(argc, argv);
		} else if (!strcmp(*argv, "sm2verify")) {
			return sm2verify_main(argc, argv);
		} else if (!strcmp(*argv, "sm2encrypt")) {
			return sm2encrypt_main(argc, argv);
		} else if (!strcmp(*argv, "sm2decrypt")) {
			return sm2decrypt_main(argc, argv);
		} else if (!strcmp(*argv, "sm3")) {
			return sm3_main(argc, argv);
		} else if (!strcmp(*argv, "sm3hmac")) {
			return sm3hmac_main(argc, argv);
		} else if (!strcmp(*argv, "sm3_pbkdf2")) {
			return sm3_pbkdf2_main(argc, argv);
		} else if (!strcmp(*argv, "sm3xmss_keygen")) {
			return sm3xmss_keygen_main(argc, argv);
#if ENABLE_SM4_ECB
		} else if (!strcmp(*argv, "sm4_ecb")) {
			return sm4_ecb_main(argc, argv);
#endif
		} else if (!strcmp(*argv, "sm4_cbc")) {
			return sm4_cbc_main(argc, argv);
		} else if (!strcmp(*argv, "sm4_ctr")) {
			return sm4_ctr_main(argc, argv);
#if ENABLE_SM4_CFB
		} else if (!strcmp(*argv, "sm4_cfb")) {
			return sm4_cfb_main(argc, argv);
#endif
#if ENABLE_SM4_OFB
		} else if (!strcmp(*argv, "sm4_ofb")) {
			return sm4_ofb_main(argc, argv);
#endif
#if ENABLE_SM4_CCM
		} else if (!strcmp(*argv, "sm4_ccm")) {
			return sm4_ccm_main(argc, argv);
#endif
		} else if (!strcmp(*argv, "sm4_gcm")) {
			return sm4_gcm_main(argc, argv);
#if ENABLE_SM4_XTS
		} else if (!strcmp(*argv, "sm4_xts")) {
			return sm4_xts_main(argc, argv);
#endif
		} else if (!strcmp(*argv, "sm4_cbc_sm3_hmac")) {
			return sm4_cbc_sm3_hmac_main(argc, argv);
		} else if (!strcmp(*argv, "sm4_ctr_sm3_hmac")) {
			return sm4_ctr_sm3_hmac_main(argc, argv);
		} else if (!strcmp(*argv, "ghash")) {
			return ghash_main(argc, argv);
#if ENABLE_SM4_CBC_MAC
		} else if (!strcmp(*argv, "sm4_cbc_mac")) {
			return sm4_cbc_mac_main(argc, argv);
#endif
		} else if (!strcmp(*argv, "zuc")) {
			return zuc_main(argc, argv);
		} else if (!strcmp(*argv, "sm9setup")) {
			return sm9setup_main(argc, argv);
		} else if (!strcmp(*argv, "sm9keygen")) {
			return sm9keygen_main(argc, argv);
		} else if (!strcmp(*argv, "sm9sign")) {
			return sm9sign_main(argc, argv);
		} else if (!strcmp(*argv, "sm9verify")) {
			return sm9verify_main(argc, argv);
		} else if (!strcmp(*argv, "sm9encrypt")) {
			return sm9encrypt_main(argc, argv);
		} else if (!strcmp(*argv, "sm9decrypt")) {
			return sm9decrypt_main(argc, argv);
		} else if (!strcmp(*argv, "cmsparse")) {
			return cmsparse_main(argc, argv);
		} else if (!strcmp(*argv, "cmsencrypt")) {
			return cmsencrypt_main(argc, argv);
		} else if (!strcmp(*argv, "cmsdecrypt")) {
			return cmsdecrypt_main(argc, argv);
		} else if (!strcmp(*argv, "cmssign")) {
			return cmssign_main(argc, argv);
		} else if (!strcmp(*argv, "cmsverify")) {
			return cmsverify_main(argc, argv);
		} else if (!strcmp(*argv, "tlcp_client")) {
			return tlcp_client_main(argc, argv);
		} else if (!strcmp(*argv, "tlcp_server")) {
			return tlcp_server_main(argc, argv);
		} else if (!strcmp(*argv, "tls12_client")) {
			return tls12_client_main(argc, argv);
		} else if (!strcmp(*argv, "tls12_server")) {
			return tls12_server_main(argc, argv);
		} else if (!strcmp(*argv, "tls13_client")) {
			return tls13_client_main(argc, argv);
		} else if (!strcmp(*argv, "tls13_server")) {
			return tls13_server_main(argc, argv);
#ifdef ENABLE_SDF
		} else if (!strcmp(*argv, "sdfinfo")) {
			return sdfinfo_main(argc, argv);
		} else if (!strcmp(*argv, "sdfdigest")) {
			return sdfdigest_main(argc, argv);
		} else if (!strcmp(*argv, "sdfexport")) {
			return sdfexport_main(argc, argv);
		} else if (!strcmp(*argv, "sdfsign")) {
			return sdfsign_main(argc, argv);
		} else if (!strcmp(*argv, "sdfencrypt")) {
			return sdfencrypt_main(argc, argv);
		} else if (!strcmp(*argv, "sdfdecrypt")) {
			return sdfdecrypt_main(argc, argv);
		} else if (!strcmp(*argv, "sdftest")) {
			return sdftest_main(argc, argv);
#endif
#ifdef ENABLE_SKF
		} else if (!strcmp(*argv, "skfutil")) {
			return skfutil_main(argc, argv);
#endif
		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			fprintf(stderr, "usage: %s %s\n", prog, options);
			return 1;
		}

		argc--;
		argv++;
	}

	return ret;
}
