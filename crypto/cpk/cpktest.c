#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include "cpk.h"
#include "kdf.h"
#include "ecies.h"


const char *id_short = "id";
const char *id_long = 
		"123456789022345678903234567890423456789052345678906234567890"
		"123456789022345678903234567890423456789052345678906234567890";



int EVP_PKEY_print_fp(const EVP_PKEY *pkey, FILE *fp)
{
	ASN1_PCTX *ctx = ASN1_PCTX_new();
	BIO *bio = BIO_new_fp(fp, BIO_NOCLOSE);

	EVP_PKEY_print_params(bio, pkey, 0, ctx);	
	EVP_PKEY_print_public(bio, pkey, 0, ctx);
	EVP_PKEY_print_private(bio, pkey, 0, NULL);

	return 0;
}

int main(int argc, char **argv)
{
	int r, i;
	KDF_FUNC kdf = NULL;
	EC_GROUP *ec_group = NULL;
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *pub_key = NULL;
	EVP_PKEY *priv_key = NULL;
	X509_ALGOR *map = NULL;
	CPK_MASTER_SECRET *master = NULL;
	CPK_PUBLIC_PARAMS *params = NULL;
	BIO *bio_out = NULL;
	unsigned char *buf = NULL;
	unsigned char *p;
	const unsigned char *cp;
	int len;

	/* init openssl global functions */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	/* prepare cpk setup parameters */
	ec_key = EC_KEY_new_by_curve_name(OBJ_sn2nid("prime192v1"));
	assert(ec_key != NULL);

	EC_GROUP_set_asn1_flag((EC_GROUP *)EC_KEY_get0_group(ec_key), OPENSSL_EC_NAMED_CURVE);
	r = EC_KEY_generate_key(ec_key);
	assert(r == 1);

	pkey = EVP_PKEY_new();
	assert(pkey != NULL);
	r = EVP_PKEY_set1_EC_KEY(pkey, ec_key);
	assert(r == 1);
	map = CPK_MAP_new_default();
	assert(map != NULL);


	//EVP_PKEY_print_fp(pkey, stdout);

	/* generate master_secret and public_params */
	master = CPK_MASTER_SECRET_create("domainid", pkey, map);
	OPENSSL_assert(master);

	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	OPENSSL_assert(bio_out);

	r = CPK_MASTER_SECRET_print(bio_out, master, 0, 0);
	assert(r == 1);

	EVP_PKEY_free(pkey);
	pkey = NULL;
	pkey = CPK_MASTER_SECRET_extract_private_key(master, "id");
	assert(pkey != NULL);
	EVP_PKEY_free(pkey);
	//pkey = CPK_MASTER_SECRET_extract_private_key(master, NULL);
	//assert(pkey == NULL);
	pkey = CPK_MASTER_SECRET_extract_private_key(master, id_long);
	assert(pkey != NULL);
	printf("EVP_PKEY of '%s':\n", id_long);
	EVP_PKEY_print_fp(pkey, stdout);
	printf("\n");
	
	params = CPK_MASTER_SECRET_extract_public_params(master);
	assert(params);
	r = CPK_PUBLIC_PARAMS_print(bio_out, params, 0, 0);
	assert(r == 1);
	printf("\n");

	printf("test CPK_PUBLIC_PARAMS_extract_public_key()\n");
	pub_key = CPK_PUBLIC_PARAMS_extract_public_key(params, id_short);
	assert(pub_key != NULL);
	EVP_PKEY_free(pub_key);

	pub_key = CPK_PUBLIC_PARAMS_extract_public_key(params, id_long);
	assert(pub_key != NULL);
	printf("Public Key of '%s':\n", id_long);
	EVP_PKEY_print_fp(pkey, stdout);
	printf("\n");

	
	r = CPK_MASTER_SECRET_validate_public_params(master, params);
	assert(r == 1);
	if (priv_key) EVP_PKEY_free(priv_key);
	priv_key = CPK_MASTER_SECRET_extract_private_key(master, "identity");
	assert(priv_key);
	r = CPK_PUBLIC_PARAMS_validate_private_key(params, "identity", priv_key);
	assert(r == 1);
	r = CPK_PUBLIC_PARAMS_validate_private_key(params, "id", priv_key);
	assert(r == 0);

	/* der encoding and decoding */
	len = i2d_CPK_MASTER_SECRET(master, NULL);
	assert(len > 0);
	if (buf != NULL) OPENSSL_free(buf);
	buf = OPENSSL_malloc(len);
	assert(buf != NULL);
	p = buf;
	len = i2d_CPK_MASTER_SECRET(master, &p);
	assert(len > 0);
	assert(p - buf == len);

	cp = buf;
	if (master) CPK_MASTER_SECRET_free(master);
	master = NULL;
	master = d2i_CPK_MASTER_SECRET(NULL, &cp, len);
	assert(master != NULL);
	r = CPK_MASTER_SECRET_validate_public_params(master, params);
	assert(r == 1);

	kdf = KDF_get_x9_63(EVP_sha1());
	assert(kdf != NULL);


	if (priv_key != NULL) EVP_PKEY_free(priv_key);
	priv_key = CPK_MASTER_SECRET_extract_private_key(master, "Alice");
	assert(priv_key != NULL);

	if (buf != NULL) OPENSSL_free(buf);
	buf = OPENSSL_malloc(1024);
	assert(buf != NULL);
	r = CPK_PUBLIC_PARAMS_compute_share_key(params, buf, 64, "Bob", priv_key, kdf);
	for (i = 0; i < 64; i++) printf("%02x", buf[i]); printf("\n");

	if (priv_key != NULL)
		EVP_PKEY_free(priv_key);
	priv_key = CPK_MASTER_SECRET_extract_private_key(master, "Bob");
	assert(priv_key != NULL);
	r = CPK_PUBLIC_PARAMS_compute_share_key(params, buf, 64, "Alice", priv_key, kdf);
	for (i = 0; i < 64; i++) printf("%02x", buf[i]); printf("\n");


	printf("ok\n");
	
	return 0;
}


