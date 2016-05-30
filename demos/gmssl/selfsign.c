#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

int mkit(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days)
{
	X509 *x;
	EVP_PKEY *pk;
	EC_KEY *ec_key;
	X509_NAME *name = NULL;
	X509_NAME_ENTRY *ne = NULL;
	X509_EXTENSION *ex = NULL;

	if ((pkeyp == NULL) || (*pkeyp == NULL)) {
		if ((pk = EVP_PKEY_new()) == NULL) {
			abort();
			return (0);
		}
	} else
		pk = *pkeyp;

	if ((x509p == NULL) || (*x509p == NULL)) {
		if ((x = X509_new()) == NULL)
			goto err;
	} else {
		x = *x509p;
	}


	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	EC_KEY_generate_key(ec_key);

	if (!EVP_PKEY_assign_EC_KEY(pk, ec_key)) {
		abort();
		goto err;
	}
	ec_key = NULL;

	X509_set_version(x, 3);
	ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * days);
	X509_set_pubkey(x, pk);

	name = X509_get_subject_name(x);

	/*
	* This function creates and adds the entry, working out the correct
	* string type and performing checks on its length. Normally we'd check
	* the return value for errors...
	*/
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, "UK", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN",
			       MBSTRING_ASC, "OpenSSL Group", -1, -1, 0);

	X509_set_issuer_name(x, name);

	/*
	* Add extension using V3 code: we can set the config file as NULL
	* because we wont reference any other sections. We can also set the
	* context to NULL because none of these extensions below will need to
	* access it.
	*/

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_cert_type, "server");
	X509_add_ext(x, ex, -1);
	X509_EXTENSION_free(ex);

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment,
			     "example comment extension");
	X509_add_ext(x, ex, -1);
	X509_EXTENSION_free(ex);

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_ssl_server_name,
			     "www.openssl.org");

	X509_add_ext(x, ex, -1);
	X509_EXTENSION_free(ex);


	if (!X509_sign(x, pk, EVP_sm3()))
	goto err;

	*x509p = x;
	*pkeyp = pk;
	return (1);
err:
	return (0);
}

int main()
{
	BIO *bio_err;
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);


	mkit(&x509, &pkey, 512, 0, 365);

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
