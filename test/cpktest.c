/* ====================================================================
 * Copyright (c) 2007 - 2016 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../e_os.h"

#ifdef OPENSSL_NO_CPK
int main(int argc, char **argv)
{
	printf("NO CPK support\n");
	return 0;
}
#else
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/kdf2.h>
# include <openssl/x509.h>
# include <openssl/ecies.h>
# include <openssl/objects.h>
# include <openssl/cpk.h>


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

	return 0;

	/* prepare cpk setup parameters */
	if (!(ec_key = EC_KEY_new_by_curve_name(OBJ_sn2nid("prime192v1")))) {
		goto end;
	}
	EC_GROUP_set_asn1_flag((EC_GROUP *)EC_KEY_get0_group(ec_key), OPENSSL_EC_NAMED_CURVE);
	r = EC_KEY_generate_key(ec_key);





	pkey = EVP_PKEY_new();
	r = EVP_PKEY_set1_EC_KEY(pkey, ec_key);
	map = CPK_MAP_new_default();


	//EVP_PKEY_print_fp(pkey, stdout);

	/* generate master_secret and public_params */
	master = CPK_MASTER_SECRET_create("domainid", pkey, map);

	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	r = CPK_MASTER_SECRET_print(bio_out, master, 0, 0);

	EVP_PKEY_free(pkey);
	pkey = NULL;
	pkey = CPK_MASTER_SECRET_extract_private_key(master, "id");
	EVP_PKEY_free(pkey);
	//pkey = CPK_MASTER_SECRET_extract_private_key(master, NULL);
	//assert(pkey == NULL);
	pkey = CPK_MASTER_SECRET_extract_private_key(master, id_long);
	EVP_PKEY_print_fp(pkey, stdout);
	params = CPK_MASTER_SECRET_extract_public_params(master);
	r = CPK_PUBLIC_PARAMS_print(bio_out, params, 0, 0);
	printf("\n");

	printf("test CPK_PUBLIC_PARAMS_extract_public_key()\n");
	pub_key = CPK_PUBLIC_PARAMS_extract_public_key(params, id_short);
	EVP_PKEY_free(pub_key);

	pub_key = CPK_PUBLIC_PARAMS_extract_public_key(params, id_long);
	printf("Public Key of '%s':\n", id_long);
	EVP_PKEY_print_fp(pkey, stdout);
	printf("\n");

	r = CPK_MASTER_SECRET_validate_public_params(master, params);
	if (priv_key) EVP_PKEY_free(priv_key);
	priv_key = CPK_MASTER_SECRET_extract_private_key(master, "identity");
	r = CPK_PUBLIC_PARAMS_validate_private_key(params, "identity", priv_key);
	r = CPK_PUBLIC_PARAMS_validate_private_key(params, "id", priv_key);

	/* der encoding and decoding */
	len = i2d_CPK_MASTER_SECRET(master, NULL);
	if (buf != NULL) OPENSSL_free(buf);
	buf = OPENSSL_malloc(len);
	p = buf;
	len = i2d_CPK_MASTER_SECRET(master, &p);

	cp = buf;
	if (master) CPK_MASTER_SECRET_free(master);
	master = NULL;
	master = d2i_CPK_MASTER_SECRET(NULL, &cp, len);
	r = CPK_MASTER_SECRET_validate_public_params(master, params);

	kdf = KDF_get_x9_63(EVP_sha1());

	if (priv_key != NULL) EVP_PKEY_free(priv_key);
	priv_key = CPK_MASTER_SECRET_extract_private_key(master, "Alice");

	if (buf != NULL) OPENSSL_free(buf);
	buf = OPENSSL_malloc(1024);
	r = CPK_PUBLIC_PARAMS_compute_share_key(params, buf, 64, "Bob", priv_key, kdf);
	for (i = 0; i < 64; i++) printf("%02x", buf[i]); printf("\n");

	if (priv_key != NULL)
		EVP_PKEY_free(priv_key);
	priv_key = CPK_MASTER_SECRET_extract_private_key(master, "Bob");
	r = CPK_PUBLIC_PARAMS_compute_share_key(params, buf, 64, "Alice", priv_key, kdf);
	for (i = 0; i < 64; i++) printf("%02x", buf[i]); printf("\n");

end:
	printf("ok\n");
	return 0;
}
#endif
