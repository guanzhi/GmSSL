#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


#define EC_MAX_NBYTES	((OPENSSL_ECC_MAX_FIELD_BITS + 7)/8)

#define SM2_MAX_ID_LENGTH 4096

/*
 * pkdata = a || b || G.x || G.y || P.x || P.y
 */
static int sm2_get_public_key_data(unsigned char *buf, EC_KEY *ec_key)
{
	int ret = -1;
	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
	const EC_POINT *point;
	int nbytes = (EC_GROUP_get_degree(ec_group) + 7) / 8;
	unsigned char oct[EC_MAX_NBYTES * 2 + 1];
	BN_CTX *bn_ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	size_t len;

	OPENSSL_assert(ec_key);
	OPENSSL_assert(nbytes == 256/8);
 
	if (!buf) {
		return (nbytes * 6);
	}
	bzero(buf, nbytes * 6);

	bn_ctx = BN_CTX_new();
	p = BN_new();
	x = BN_new();
	y = BN_new();
	if (!bn_ctx || !p || !x || !y) {
		goto err;
	}

	/* get curve coefficients a, b */
	if (!EC_GROUP_get_curve_GFp(ec_group, p, x, y, bn_ctx)) {
		goto err;
	}
	buf += nbytes;
	if (!BN_bn2bin(x, buf - BN_num_bytes(x))) {
		goto err;
	}
	buf += nbytes;
	if (!BN_bn2bin(y, buf - BN_num_bytes(y))) {
		goto err;
	}

	/* get curve generator coordinates */
	if (!(point = EC_GROUP_get0_generator(ec_group))) {
		goto err;
	}
	if (!(len = EC_POINT_point2oct(ec_group, point,
		POINT_CONVERSION_UNCOMPRESSED, oct, sizeof(oct), bn_ctx))) {
		goto err;
	}
	OPENSSL_assert(len == 32 * 2 + 1); 
	memcpy(buf, oct + 1, len - 1);
	buf += len - 1;

	/* get pub_key coorindates */
	if (!(point = EC_KEY_get0_public_key(ec_key))) {
		goto err;
	}
	if (!(len = EC_POINT_point2oct(ec_group, point,
		POINT_CONVERSION_UNCOMPRESSED, oct, sizeof(oct), bn_ctx))) {
		goto err;
	}
	OPENSSL_assert(len == 32 * 2 + 1); 
	memcpy(buf, oct + 1, len - 1);
	buf += len - 1;

	ret = (nbytes * 6);
err:
	if (bn_ctx) BN_CTX_free(bn_ctx);
	if (p) BN_free(p);
	if (x) BN_free(x);
	if (y) BN_free(y);

	return ret;
}

int SM2_compute_za(unsigned char *za, unsigned int *zalen,
	const EVP_MD *md, const void *id, size_t idlen, EC_KEY *ec_key)
{
        int ret = 0;
        EVP_MD_CTX *md_ctx = NULL;
        unsigned char pkdata[EC_MAX_NBYTES * 6];
	uint16_t idbits = idlen * 8;
	int pkdatalen;
	
	if ((pkdatalen = sm2_get_public_key_data(pkdata, ec_key)) < 0) {
		goto err;
	}

	if (!(md_ctx = EVP_MD_CTX_create())) {
		goto err;
	}
	if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
		goto err;
	}
	if (!EVP_DigestUpdate(md_ctx, &idbits, sizeof(idbits))) {
		goto err;
	}
	if (!EVP_DigestUpdate(md_ctx, id, idlen)) {
		goto err;
	}
	if (!EVP_DigestUpdate(md_ctx, pkdata, pkdatalen)) {
		goto err;
	}
	if (!EVP_DigestFinal(md_ctx, za, zalen)) {
		goto err;
	}

	ret = 1;

err:
	if (md_ctx) EVP_MD_CTX_destroy(md_ctx);
        return ret;
}

int SM2_compute_digest(unsigned char *dgst, unsigned int *dgstlen,
	const EVP_MD *za_md, const void *id, size_t idlen, EC_KEY *ec_key,
	const EVP_MD *msg_md, const void *msg, size_t msglen)
{
	int ret = 0;
	unsigned char za[EVP_MAX_MD_SIZE];
	unsigned int zalen;
	EVP_MD_CTX *ctx = NULL;

	/* compute Za */	
	if (idlen > SM2_MAX_ID_LENGTH) {
		goto err;
	}
	if (!SM2_compute_za(za, &zalen, za_md, id, idlen, ec_key)) {
		goto err;
	}

	/* compute digest */
	if (!(ctx = EVP_MD_CTX_create())) {
		goto err;
	}
	if (!EVP_DigestInit_ex(ctx, msg_md, NULL)) {
		goto err;
	}
	if (!EVP_DigestUpdate(ctx, za, zalen)) {
		goto err;
	}
	if (!EVP_DigestUpdate(ctx, msg, msglen)) {
		goto err;
	}
	if (!EVP_DigestFinal_ex(ctx, dgst, dgstlen)) {
		goto err;
	}

	ret = 1;

err:
	if (ctx) EVP_MD_CTX_destroy(ctx);
	return ret;
}

