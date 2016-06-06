#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

int main()
{
	BIO *bio_err;

	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	int serial = 123;
	int days = 365;
	X509_NAME *name = NULL;
	X509_NAME_ENTRY *ne = NULL;
	X509_EXTENSION *ex = NULL;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	EC_KEY_generate_key(ec_key);
	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_EC_KEY(pkey, ec_key);
	ec_key = NULL;

	x509 = X509_new();
	X509_set_version(x509, 3);
	ASN1_INTEGER_set(X509_get_serialNumber(x509), serial);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * days);
	X509_set_pubkey(x509, pkey);

	name = X509_get_subject_name(x509);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, "UK", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "OpenSSL Group", -1, -1, 0);
	X509_set_issuer_name(x509, name);

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_cert_type, "server");
	X509_add_ext(x509, ex, -1);
	X509_EXTENSION_free(ex);

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment, "example comment extension");
	X509_add_ext(x509, ex, -1);
	X509_EXTENSION_free(ex);

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_ssl_server_name, "www.openssl.org");

	X509_add_ext(x509, ex, -1);
	X509_EXTENSION_free(ex);

	X509_sign(x509, pkey, EVP_sm3());

	EC_KEY_print_fp(stdout, pkey->pkey.ec, 0);
	X509_print_fp(stdout, x509);

	PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
	PEM_write_X509(stdout, x509);

	X509_free(x509);
	EVP_PKEY_free(pkey);

	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);

	return (0);
}
