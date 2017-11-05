/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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

#include <string.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/kdf.h>
#include "sm2_lcl.h"

int SM2_KAP_CTX_init(SM2_KAP_CTX *ctx,
	EC_KEY *ec_key, const char *id, size_t idlen,
	EC_KEY *remote_pubkey, const char *rid, size_t ridlen,
	int is_initiator, int do_checksum)
{
	int ret = 0;
	int w;
	size_t len;

	if (!ctx || !ec_key || !remote_pubkey) {
		ECerr(EC_F_SM2_KAP_CTX_INIT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->id_dgstlen = sizeof(ctx->id_dgst);
	ctx->remote_id_dgstlen = sizeof(ctx->remote_id_dgst);

	ctx->id_dgst_md = EVP_sm3();
	ctx->kdf_md = EVP_sm3();
	ctx->checksum_md = EVP_sm3();
	ctx->point_form = SM2_DEFAULT_POINT_CONVERSION_FORM;

	if (!(ctx->kdf = KDF_get_x9_63(ctx->kdf_md))) {
		ECerr(EC_F_SM2_KAP_CTX_INIT, EC_R_INVALID_KDF_MD);
		goto end;
	}

	ctx->is_initiator = is_initiator;
	ctx->do_checksum = do_checksum;

	if (EC_GROUP_cmp(EC_KEY_get0_group(ec_key),
		EC_KEY_get0_group(remote_pubkey), NULL) != 0) {
		ECerr(EC_F_SM2_KAP_CTX_INIT, 0);
		goto end;
	}

	len = ctx->id_dgstlen;
	if (!SM2_compute_id_digest(ctx->id_dgst_md, id, idlen,
		ctx->id_dgst, &len, ec_key)) {
		ECerr(EC_F_SM2_KAP_CTX_INIT, 0);
		goto end;
	}
	ctx->id_dgstlen = len;

	if (!(ctx->ec_key = EC_KEY_dup(ec_key))) {
		ECerr(EC_F_SM2_KAP_CTX_INIT, ERR_R_EC_LIB);
		goto end;
	}

	len = ctx->remote_id_dgstlen;
	if (!SM2_compute_id_digest(ctx->id_dgst_md, rid, ridlen,
		ctx->remote_id_dgst, &len, remote_pubkey)) {
		ECerr(EC_F_SM2_KAP_CTX_INIT, 0);
		goto end;
	}
	ctx->remote_id_dgstlen = len;

	if (!(ctx->remote_pubkey = EC_KEY_dup(remote_pubkey))) {
		ECerr(EC_F_SM2_KAP_CTX_INIT, 0);
		goto end;
	}

	ctx->group = EC_KEY_get0_group(ec_key);
	ctx->bn_ctx = BN_CTX_new();
	ctx->order = BN_new();
	ctx->two_pow_w = BN_new();
	ctx->t = BN_new();

	if (!ctx->bn_ctx || !ctx->order || !ctx->two_pow_w || !ctx->t) {
		ECerr(EC_F_SM2_KAP_CTX_INIT, ERR_R_BN_LIB);
		goto end;
	}

	if (!EC_GROUP_get_order(EC_KEY_get0_group(ec_key), ctx->order, ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_CTX_INIT, ERR_R_EC_LIB);
		goto end;
	}

	w = (BN_num_bits(ctx->order) + 1)/2 - 1;

	if (!BN_one(ctx->two_pow_w)) {
		ECerr(EC_F_SM2_KAP_CTX_INIT, ERR_R_BN_LIB);
		goto end;
	}

	if (!BN_lshift(ctx->two_pow_w, ctx->two_pow_w, w)) {
		ECerr(EC_F_SM2_KAP_CTX_INIT, ERR_R_BN_LIB);
		goto end;
	}

	if (!(ctx->point = EC_POINT_new(ctx->group))) {
		ECerr(EC_F_SM2_KAP_CTX_INIT, ERR_R_EC_LIB);
		goto end;
	}

	ret = 1;

end:
	if (!ret) SM2_KAP_CTX_cleanup(ctx);
	return ret;
}

void SM2_KAP_CTX_cleanup(SM2_KAP_CTX *ctx)
{
	if (ctx) {
		EC_KEY_free(ctx->ec_key);
		EC_KEY_free(ctx->remote_pubkey);
		BN_CTX_free(ctx->bn_ctx);
		BN_free(ctx->two_pow_w);
		BN_free(ctx->order);
		EC_POINT_free(ctx->point);
		BN_free(ctx->t);
		memset(ctx, 0, sizeof(*ctx));
	}
}

/* FIXME: ephem_point_len should be both input and output */
int SM2_KAP_prepare(SM2_KAP_CTX *ctx, unsigned char *ephem_point,
	size_t *ephem_point_len)
{
	int ret = 0;
	const BIGNUM *prikey;
	BIGNUM *h = NULL;
	BIGNUM *r = NULL;
	BIGNUM *x = NULL;

	if (!(prikey = EC_KEY_get0_private_key(ctx->ec_key))) {
		ECerr(EC_F_SM2_KAP_PREPARE, EC_R_SM2_KAP_NOT_INITED);
		return 0;
	}

	h = BN_new();
	r = BN_new();
	x = BN_new();

	if (!h || !r || !x) {
		ECerr(EC_F_SM2_KAP_PREPARE, 0);
		goto end;
	}

	/*
	 * r = rand(1, n)
	 * R = rG = (x, y)
	 */

	do {
		if (!BN_rand_range(r, ctx->order)) {
			ECerr(EC_F_SM2_KAP_PREPARE, EC_R_RANDOM_NUMBER_GENERATION_FAILED);
			goto end;
		}

	} while (BN_is_zero(r));


	if (!EC_POINT_mul(ctx->group, ctx->point, r, NULL, NULL, ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_PREPARE, ERR_R_EC_LIB);
		goto end;
	}


	if (EC_METHOD_get_field_type(EC_GROUP_method_of(ctx->group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(ctx->group, ctx->point, x, NULL, ctx->bn_ctx)) {
			ECerr(EC_F_SM2_KAP_PREPARE, ERR_R_EC_LIB);
			goto end;
		}
	} else {
		if (!EC_POINT_get_affine_coordinates_GF2m(ctx->group, ctx->point, x, NULL, ctx->bn_ctx)) {
			ECerr(EC_F_SM2_KAP_PREPARE, ERR_R_EC_LIB);
			goto end;
		}
	}

	/*
	 * w = ceil(keybits / 2) - 1
	 * x = 2^w + (x and (2^w - 1)) = 2^w + (x mod 2^w)
	 * t = (d + x * r) mod n
	 * t = (h * t) mod n
	 */

	if (!ctx->t) {
		ECerr(EC_F_SM2_KAP_PREPARE, EC_R_SM2_KAP_NOT_INITED);
		goto end;
	}

	if (!BN_nnmod(x, x, ctx->two_pow_w, ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_PREPARE, ERR_R_BN_LIB);
		goto end;
	}

	if (!BN_add(x, x, ctx->two_pow_w)) {
		ECerr(EC_F_SM2_KAP_PREPARE, ERR_R_BN_LIB);
		goto end;
	}

	if (!BN_mod_mul(ctx->t, x, r, ctx->order, ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_PREPARE, ERR_R_BN_LIB);
		goto end;
	}

	if (!BN_mod_add(ctx->t, ctx->t, prikey, ctx->order, ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_PREPARE, ERR_R_BN_LIB);
		goto end;
	}

	if (!EC_GROUP_get_cofactor(ctx->group, h, ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_PREPARE, ERR_R_EC_LIB);
		goto end;
	}

	if (!BN_mul(ctx->t, ctx->t, h, ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_PREPARE, ERR_R_BN_LIB);
		goto end;
	}

	/* encode R = (x, y) for output and local buffer */

	// FIXME: ret is size_t and ret is the output length
	ret = EC_POINT_point2oct(ctx->group, ctx->point, ctx->point_form,
		ephem_point, *ephem_point_len, ctx->bn_ctx);

	memcpy(ctx->pt_buf, ephem_point, ret);
	*ephem_point_len = ret;
	ret = 1;

end:
	if (h) BN_free(h);
	if (r) BN_free(r);
	if (x) BN_free(x);

	return ret;
}

int SM2_KAP_compute_key(SM2_KAP_CTX *ctx, const unsigned char *remote_point,
	size_t remote_point_len, unsigned char *key, size_t keylen,
	unsigned char *checksum, size_t *checksumlen)
{
	int ret = 0;

	EVP_MD_CTX *md_ctx = NULL;
	BIGNUM *x = NULL;
	unsigned char share_pt_buf[1 + (OPENSSL_ECC_MAX_FIELD_BITS+7)/4 + EVP_MAX_MD_SIZE * 2 + 100];
	unsigned char remote_pt_buf[1 + (OPENSSL_ECC_MAX_FIELD_BITS+7)/4 + 111];
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	unsigned int len, bnlen;
	size_t klen = keylen;

	md_ctx = EVP_MD_CTX_new();
	x = BN_new();
	if (!md_ctx || !x) {
		ECerr(EC_F_SM2_KAP_COMPUTE_KEY, 0);
		goto end;
	}

	/*
	 * decode point R = (x, y), encode (x, y)
	 * x = 2^w + (x and (2^w - 1)) = 2^w + (x mod 2^w), w = ceil(keybits / 2) - 1
	 * U = ht * (P + x * R)
	 * check U != O
	 */

	if (!EC_POINT_oct2point(ctx->group, ctx->point,
		remote_point, remote_point_len, ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_COMPUTE_KEY, 0);
		goto end;
	}

	if (!(len = EC_POINT_point2oct(ctx->group, ctx->point, POINT_CONVERSION_UNCOMPRESSED,
		remote_pt_buf, sizeof(remote_pt_buf), ctx->bn_ctx))) {
		ECerr(EC_F_SM2_KAP_COMPUTE_KEY, 0);
		goto end;
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(ctx->group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(ctx->group, ctx->point, x, NULL, ctx->bn_ctx)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
			goto end;
		}
	} else {
		if (!EC_POINT_get_affine_coordinates_GF2m(ctx->group, ctx->point, x, NULL, ctx->bn_ctx)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
			goto end;
		}
	}

	/* x = 2^w + (x and (2^w - 1)) = 2^w + (x mod 2^w) */

	if (!BN_nnmod(x, x, ctx->two_pow_w, ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_BN_LIB);
		goto end;
	}

	if (!BN_add(x, x, ctx->two_pow_w)) {
		ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/*
	if (!BN_mod_mul(x, x, ctx->t, ctx->order, ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_BN_LIB);
		goto end;
	}
	*/

	/* U = ht * (P + x * R), check U != O */

	if (!EC_POINT_mul(ctx->group, ctx->point, NULL, ctx->point, x, ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
		goto end;
	}

	if (!EC_POINT_add(ctx->group, ctx->point, ctx->point,
		EC_KEY_get0_public_key(ctx->remote_pubkey), ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
		goto end;
	}

	if (!EC_POINT_mul(ctx->group, ctx->point, NULL, ctx->point, ctx->t, ctx->bn_ctx)) {
		ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
		goto end;
	}

	if (EC_POINT_is_at_infinity(ctx->group, ctx->point)) {
		ECerr(EC_F_SM2_KAP_COMPUTE_KEY, 0);
		goto end;
	}

	/* encode U, append with ZA, ZB */

	if (!(len = EC_POINT_point2oct(ctx->group, ctx->point, POINT_CONVERSION_UNCOMPRESSED,
		share_pt_buf, sizeof(share_pt_buf), ctx->bn_ctx))) {
		ECerr(EC_F_SM2_KAP_COMPUTE_KEY, 0);
		goto end;
	}

	if (ctx->is_initiator) {
		memcpy(share_pt_buf + len, ctx->id_dgst, ctx->id_dgstlen);
		len += ctx->id_dgstlen;
		memcpy(share_pt_buf + len, ctx->remote_id_dgst, ctx->remote_id_dgstlen);
		len += ctx->remote_id_dgstlen;
	} else {
		memcpy(share_pt_buf + len, ctx->remote_id_dgst, ctx->remote_id_dgstlen);
		len += ctx->remote_id_dgstlen;
		memcpy(share_pt_buf + len, ctx->id_dgst, ctx->id_dgstlen);
		len += ctx->id_dgstlen;
	}

	/* key = KDF(xu, yu, ZA, ZB) */


	if (!ctx->kdf(share_pt_buf + 1, len - 1, key, &klen)) {
		ECerr(EC_F_SM2_KAP_COMPUTE_KEY, 0);
		goto end;
	}

	if (ctx->do_checksum) {

		/* generate checksum S1 or SB start with 0x02
		 * S1 = SB = Hash(0x02, yu, Hash(xu, ZA, ZB, x1, y1, x2, y2))
		 */
		if (!EVP_DigestInit_ex(md_ctx, ctx->checksum_md, NULL)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
			goto end;
		}

		bnlen = BN_num_bytes(ctx->order);

		if (!EVP_DigestUpdate(md_ctx, share_pt_buf + 1, bnlen)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
			goto end;
		}

		if (ctx->is_initiator) {

			/* update ZA,ZB,x1,y1,x2,y2 */
			if (!EVP_DigestUpdate(md_ctx, ctx->id_dgst, ctx->id_dgstlen)) {
				ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
				goto end;
			}
			if (!EVP_DigestUpdate(md_ctx, ctx->remote_id_dgst, ctx->remote_id_dgstlen)) {
				ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
				goto end;
			}
			if (!EVP_DigestUpdate(md_ctx, ctx->pt_buf + 1, bnlen * 2)) {
				ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
				goto end;
			}
			if (!EVP_DigestUpdate(md_ctx, remote_pt_buf + 1, bnlen * 2)) {
				ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
				goto end;
			}

		} else {

			if (!EVP_DigestUpdate(md_ctx, ctx->remote_id_dgst, ctx->remote_id_dgstlen)) {
				ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
				goto end;
			}
			if (!EVP_DigestUpdate(md_ctx, ctx->id_dgst, ctx->id_dgstlen)) {
				ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
				goto end;
			}
			if (!EVP_DigestUpdate(md_ctx, remote_pt_buf + 1, bnlen * 2)) {
				ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
				goto end;
			}
			if (!EVP_DigestUpdate(md_ctx, ctx->pt_buf + 1, bnlen * 2)) {
				ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
				goto end;
			}
		}

		if (!EVP_DigestFinal_ex(md_ctx, dgst, &dgstlen)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
			goto end;
		}
		/* now dgst == H(xu,ZA,ZB,x1,y1,x2,y2)
		 */

		/* S1 = SB = Hash(0x02, yu, dgst) */

		if (!EVP_DigestInit_ex(md_ctx, ctx->checksum_md, NULL)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
			goto end;
		}

		if (!EVP_DigestUpdate(md_ctx, "\x02", 1)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
			goto end;
		}

		if (!EVP_DigestUpdate(md_ctx, share_pt_buf + 1 + bnlen, bnlen)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
			goto end;
		}

		if (!EVP_DigestUpdate(md_ctx, dgst, dgstlen)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
			goto end;
		}

		/* output S1 to local buffer or SB to output */
		if (ctx->is_initiator) {
			if (!EVP_DigestFinal_ex(md_ctx, ctx->checksum, &len)) {
				ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
				goto end;
			}

		} else {
			if (!EVP_DigestFinal_ex(md_ctx, checksum, &len)) {
				ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
				goto end;
			}
			*checksumlen = len;
		}

		/* generate checksum SA or S2 start with 0x03
		 * SA = S2 = Hash(0x03, yu, dgst)
		 */

		if (!EVP_DigestInit_ex(md_ctx, ctx->checksum_md, NULL)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
			goto end;
		}

		if (!EVP_DigestUpdate(md_ctx, "\x03", 1)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
			goto end;
		}

		if (!EVP_DigestUpdate(md_ctx, share_pt_buf + 1 + bnlen, bnlen)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
			goto end;
		}

		if (!EVP_DigestUpdate(md_ctx, dgst, dgstlen)) {
			ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
			goto end;
		}

		if (ctx->is_initiator) {
			if (!EVP_DigestFinal_ex(md_ctx, checksum, &len)) {
				ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
				goto end;
			}
			*checksumlen = len;

		} else {
			if (!EVP_DigestFinal_ex(md_ctx, ctx->checksum, &len)) {
				ECerr(EC_F_SM2_KAP_COMPUTE_KEY, ERR_R_EVP_LIB);
				goto end;
			}
		}


	}

	ret = 1;

end:
	EVP_MD_CTX_free(md_ctx);
	BN_free(x);
	return ret;
}

int SM2_KAP_final_check(SM2_KAP_CTX *ctx, const unsigned char *checksum,
	size_t checksumlen)
{
	if (ctx->do_checksum) {
		if (checksumlen != EVP_MD_size(ctx->checksum_md)) {
			ECerr(EC_F_SM2_KAP_FINAL_CHECK, EC_R_INVALID_SM2_KAP_CHECKSUM_LENGTH);
			return 0;
		}
		if (memcmp(ctx->checksum, checksum, checksumlen)) {
			ECerr(EC_F_SM2_KAP_FINAL_CHECK, EC_R_INVALID_SM2_KAP_CHECKSUM_VALUE);
			return 0;
		}
	}

	return 1;
}

int SM2_compute_share_key(unsigned char *out, size_t *outlen,
	const EC_POINT *peer_ephem, EC_KEY *ephem,
	const EC_POINT *peer_pk, const unsigned char *peer_z, size_t peer_zlen,
	const unsigned char *z, size_t zlen, EC_KEY *sk, int initiator)
{
	memset(out, 1, *outlen);
	return 1;
}
