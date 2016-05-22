#include <stdio.h>
#include <strings.h>
#include <openssl/sm2.h>
#include <openssl/rsa.h>
#include "skf.h"

int EC_KEY_set_ECCPUBLICKEYBLOB(EC_KEY *ec_key, const ECCPUBLICKEYBLOB *blob)
{
	int ret = 0;
	int nbytes;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;

	if (blob->BitLen != EC_GROUP_get_degree(EC_KEY_get0_group(ec_key))) {
		return 0;
	}

	nbytes = (blob->BitLen + 7)/8;

	if (!(x = BN_bin2bn(blob->XCoordinate, nbytes, NULL))) {
		goto end;
	}
	if (!(y = BN_bin2bn(blob->YCoordinate, nbytes, NULL))) {
		goto end;
	}
	if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
		goto end;
	}

	ret = 1;
end:
	BN_free(x);
	BN_free(y);
	return ret;
}

int EC_KEY_get_ECCPUBLICKEYBLOB(EC_KEY *ec_key, ECCPUBLICKEYBLOB *blob)
{
	int ret = 0;
	int nbytes;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BN_CTX *bn_ctx = NULL;
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	const EC_POINT *point = EC_KEY_get0_public_key(ec_key);

	nbytes = (EC_GROUP_get_degree(group) + 7)/8;
	if (nbyte > ECC_MAX_MODULUS_BITS_LEN/8) {
		goto end;
	}

	x = BN_new();
	y = BN_new();
	bn_ctx = BN_CTX_new();
	if (!x || !y || !bn_ctx) {
		goto end;
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bn_ctx)) {
			goto end;
		}
	} else  {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, point, x, y, bn_ctx)) {
			goto end;
		}
	}

	bzero(blob, sizeof(*blob));
	blob->BitLen = EC_GROUP_get_degree(group);
	if (!BN_bn2bin(x, blob->XCoordinate + nbytes - BN_num_bytes(x))) {
		goto end;
	}
	if (!BN_bn2bin(y, blob->YCoordinate + nbytes - BN_num_bytes(y))) {
		goto end;
	}

	ret = 1;
end:
	BN_free(x);
	BN_free(y);
	BN_CTX_free(bn_ctx);
	return ret;
}

int EC_KEY_set_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, const ECCPRIVATEKEYBLOB *blob)
{
	int ret = 0;
	int nbytes;
	BIGNUM *d = NULL;

	/* is this corrent ?
	 * because the key length sometimes will be less than field length
	 */
	if (blob->BitLen != EC_GROUP_get_degree(EC_KEY_get0_group(ec_key))) {
		goto end;
	}

	nbytes = (blob->BitLen + 7)/8;
	if (!(d = BN_bin2bn(data->PrivateKey, nbytes, NULL))) {
		goto end;
	}
	if (!EC_KEY_set_private_key(ec_key, d)) {
		goto end;
	}

	ret = 1;
end:
	BN_clear_free(d);
	return ret;
}

int EC_KEY_get_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, ECCPRIVATEKEYBLOB *blob)
{
	int ret = 0;
	int nbytes;
	BIGNUM *order = BN_new();
	BIGNUM *d = EC_KEY_get0_private_key(ec_key);

	if (!order) {
		goto end;
	}

	if (!d) {
		goto end;
	}

	

	if (!EC_GROUP_get_order(EC_KEY_get0_group(ec_key), order, NULL)) {
		goto end;
	}

	nbytes = BN_num_bytes(order);
	if (nbytes > ECC_MAX_MODULUS_BITS_LEN/8) {
		goto end;
	}

	BN_bn2bin(d, blob->PrivateKey + nbytes - BN_num_bytes(d));

	ret = 1;

end:
	BN_free(order);
	return ret;	
}

int SM2_CIPHERTEXT_VALUE_set_ECCCIPHERBLOB(SM2_CIPHERTEXT_VALUE *cv,
	const ECCCIPHERBLOB *blob)
{
	SM2_CIPHERTEXT_VALUE *ret = NULL;		
	const ECCCIPHERBLOB *data = (const ECCCIPHERBLOB *)blob;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	
	if (bloblen < sizeof(ECCCIPHERBLOB)) {
		goto end;
	}

	if (!(ret = OPENSSL_malloc(sizeof(SM2_CIPHERTEXT_VALUE)))) {
		goto end;
	}
}

int SM2_CIPHERTEXT_VALUE_get_ECCCIPHERBLOB(const SM2_CIPHERTEXT_VALUE *a,
	void *out, size_t *outlen)
{
	int ret = 0;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	

	return 0;
}

ECDSA_SIG *ECDSA_SIG_new_from_SKF_ECCSIGNATUREBLOB(
	const EC_GROUP *group, const void *blob, size_t bloblen)
{
	ECDSA_SIG *ret = NULL;
	int bnlen;
	const ECCSIGNATUREBLOB *data = blob;

	if (bloblen != sizeof(ECCSIGNATUREBLOB)) {
		return NULL;
	}

	bnlen = (EC_GROUP_get_degree(group) + 7)/8;

	if (!(ret = ECDSA_SIG_new())) {
		return NULL;
	}

	ret->r = BN_bin2bn(data->r, bnlen, NULL);
	ret->s = BN_bin2bn(data->s, bnlen, NULL);

	return ret;
}

int ECDSA_SIG_to_SKF_ECCSIGNATUREBLOB(const ECDSA_SIG *sig,
	const EC_GROUP *group, void *out, size_t *outlen)
{
	int bnlen;
	ECCSIGNATUREBLOB *data = out;

	if (!out) {
		if (!outlen) {
			return 0;
		}
		*outlen = sizeof(ECCSIGNATUREBLOB);
		return 1;
	}
	
	bnlen = (EC_GROUP_get_degree(group) + 7)/8;
	*outlen = sizeof(ECCSIGNATUREBLOB);
	
	BN_bn2bin(sig->r, data->r + bnlen - BN_num_bytes(sig->r));
	BN_bn2bin(sig->s, data->s + bnlen - BN_num_bytes(sig->s));

	return 1;
}

int RSA_set_RSAPUBLICKEYBLOB(RSA *rsa, const RSAPUBLICKEYBLOB *blob)
{
	int ret = 0;

	if (!(rsa->n = BN_bin2bn(blob->Modulus, blob->BitLen/8, NULL))) {
		goto end;
	}
	if (!(rsa->e = BN_bin2bn(blob->PublicExponent, blob->BitLen/8, NULL))) {
		goto end;
	}
	if (!RSA_check_key(rsa)) {
		goto end;
	}

end:
	return ret;
}

int RSA_get_RSAPUBLICKEYBLOB(RSA *rsa, RSAPUBLICKEYBLOB *blob)
{
	int ret = 0;
	int nbytes;

	if (!rsa->n || !rsa->e) {
		goto end;
	}

	nbytes = BN_num_bytes(rsa->n);

	BN_bn2bin(rsa->n, blob->Modulus + bnlen - BN_num_bytes(rsa->n));
	BN_bn2bin(rsa->e, blob->PublicExponent + bnlen - BN_num_bytes(rsa->e));

	return ret;
}

int RSA_set_RSAPRIVATEKEYBLOB(RSA *rsa, const RSAPRIVATEKEYBLOB *blob)
{
	int ret = 0;

	if (!blob->AlgID) {
		goto end;
	}
	if (!blob->BitLen) {
		goto end;
	}

	rsa->n = BN_bin2bn(blob->Modulus, MAX_RSA_MODULUS_LEN, NULL);
	rsa->e = BN_bin2bn(blob->PublicExponent, MAX_RSA_EXPONENT_LEN, NULL);
	rsa->d = BN_bin2bn(blob->Prime1, bnlen, NULL);
	rsa->p = BN_bin2bn(blob->Prime2, bnlen, NULL);
	rsa->dmp1 = BN_bin2bn(blob->Prime1Exponent, bnlen, NULL);
	rsa->dmq1 = BN_bin2bn(blob->Prime2Exponent, bnlen, NULL);
	rsa->iqmp = BN_bin2bn(blob->Coefficient, bnlen, NULL);

}

int RSA_get_RSAPRIVATEKEYBLOB(RSA *rsa, RSAPRIVATEKEYBLOB *blob)
{
	int ret = 0;
	RSAPRIVATEKEYBLOB *blob = out;
	
	return ret;
}

