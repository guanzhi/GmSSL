/* crypto/ecdsa/ecs_sm2.c */

#include "ecs_locl.h"
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

static ECDSA_SIG *sm2dsa_do_sign(const unsigned char *dgst, int dlen, const BIGNUM *, const BIGNUM *, EC_KEY *eckey);
static int sm2dsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);
static int sm2dsa_do_verify(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig, EC_KEY *eckey);

static ECDSA_METHOD sm2dsa_meth = {
	"SM2 DSA method",
	sm2_do_sign,
	sm2_sign_setup,
	sm2_do_verify,
#if 0
	NULL, /* init     */
	NULL, /* finish   */
#endif
	0,    /* flags    */
	NULL  /* app_data */
};

const ECDSA_METHOD *ECDSA_SM2DSA(void)
{
	return &openssl_ecdsa_meth;
}

static int ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
		BIGNUM **rp)
{
	return 1;
}


static ECDSA_SIG *ecdsa_do_sign(const unsigned char *dgst, int dgst_len, 
		const BIGNUM *in_kinv, const BIGNUM *in_r, EC_KEY *eckey)
{
	int     ok = 0, i;
	BIGNUM *kinv=NULL, *s, *m=NULL,*tmp=NULL,*order=NULL;
	const BIGNUM *ckinv;
	BN_CTX     *ctx = NULL;
	const EC_GROUP   *group;
	ECDSA_SIG  *ret;
	ECDSA_DATA *ecdsa;
	const BIGNUM *priv_key;

	ecdsa    = ecdsa_check(eckey);
	group    = EC_KEY_get0_group(eckey);
	priv_key = EC_KEY_get0_private_key(eckey);
	
	if (group == NULL || priv_key == NULL || ecdsa == NULL)
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	ret = ECDSA_SIG_new();
	if (!ret)
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	s = ret->s;

	if ((ctx = BN_CTX_new()) == NULL || (order = BN_new()) == NULL ||
		(tmp = BN_new()) == NULL || (m = BN_new()) == NULL)
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!EC_GROUP_get_order(group, order, ctx))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
		goto err;
	}
	i = BN_num_bits(order);
	/* Need to truncate digest if it is too long: first truncate whole
	 * bytes.
	 */
	if (8 * dgst_len > i)
		dgst_len = (i + 7)/8;
	if (!BN_bin2bn(dgst, dgst_len, m))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
		goto err;
	}
	/* If still too long truncate remaining bits with a shift */
	if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7)))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
		goto err;
	}
	do
	{
		if (in_kinv == NULL || in_r == NULL)
		{
			if (!ECDSA_sign_setup(eckey, ctx, &kinv, &ret->r))
			{
				ECDSAerr(ECDSA_F_ECDSA_DO_SIGN,ERR_R_ECDSA_LIB);
				goto err;
			}
			ckinv = kinv;
		}
		else
		{
			ckinv  = in_kinv;
			if (BN_copy(ret->r, in_r) == NULL)
			{
				ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
				goto err;
			}
		}

		if (!BN_mod_mul(tmp, priv_key, ret->r, order, ctx))
		{
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_add_quick(s, tmp, m, order))
		{
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_mul(s, s, ckinv, order, ctx))
		{
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (BN_is_zero(s))
		{
			/* if kinv and r have been supplied by the caller
			 * don't to generate new kinv and r values */
			if (in_kinv != NULL && in_r != NULL)
			{
				ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ECDSA_R_NEED_NEW_SETUP_VALUES);
				goto err;
			}
		}
		else
			/* s != 0 => we have a valid signature */
			break;
	}
	while (1);

	ok = 1;
err:
	if (!ok)
	{
		ECDSA_SIG_free(ret);
		ret = NULL;
	}
	if (ctx)
		BN_CTX_free(ctx);
	if (m)
		BN_clear_free(m);
	if (tmp)
		BN_clear_free(tmp);
	if (order)
		BN_free(order);
	if (kinv)
		BN_clear_free(kinv);
	return ret;
}

static int ecdsa_do_verify(const unsigned char *dgst, int dgst_len,
		const ECDSA_SIG *sig, EC_KEY *eckey)
{
	int ret = -1, i;
	BN_CTX   *ctx;
	BIGNUM   *order, *u1, *u2, *m, *X;
	EC_POINT *point = NULL;
	const EC_GROUP *group;
	const EC_POINT *pub_key;

	/* check input values */
	if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL ||
	    (pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL)
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_MISSING_PARAMETERS);
		return -1;
	}

	ctx = BN_CTX_new();
	if (!ctx)
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		return -1;
	}
	BN_CTX_start(ctx);
	order = BN_CTX_get(ctx);	
	u1    = BN_CTX_get(ctx);
	u2    = BN_CTX_get(ctx);
	m     = BN_CTX_get(ctx);
	X     = BN_CTX_get(ctx);
	if (!X)
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	
	if (!EC_GROUP_get_order(group, order, ctx))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
		goto err;
	}

	if (BN_is_zero(sig->r)          || BN_is_negative(sig->r) || 
	    BN_ucmp(sig->r, order) >= 0 || BN_is_zero(sig->s)  ||
	    BN_is_negative(sig->s)      || BN_ucmp(sig->s, order) >= 0)
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_BAD_SIGNATURE);
		ret = 0;	/* signature is invalid */
		goto err;
	}
	/* calculate tmp1 = inv(S) mod order */
	if (!BN_mod_inverse(u2, sig->s, order, ctx))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	/* digest -> m */
	i = BN_num_bits(order);
	/* Need to truncate digest if it is too long: first truncate whole
	 * bytes.
	 */
	if (8 * dgst_len > i)
		dgst_len = (i + 7)/8;
	if (!BN_bin2bn(dgst, dgst_len, m))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	/* If still too long truncate remaining bits with a shift */
	if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7)))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	/* u1 = m * tmp mod order */
	if (!BN_mod_mul(u1, m, u2, order, ctx))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	/* u2 = r * w mod q */
	if (!BN_mod_mul(u2, sig->r, u2, order, ctx))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}

	if ((point = EC_POINT_new(group)) == NULL)
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!EC_POINT_mul(group, point, u1, pub_key, u2, ctx))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
		goto err;
	}
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
	{
		if (!EC_POINT_get_affine_coordinates_GFp(group,
			point, X, NULL, ctx))
		{
			ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
			goto err;
		}
	}
	else /* NID_X9_62_characteristic_two_field */
	{
		if (!EC_POINT_get_affine_coordinates_GF2m(group,
			point, X, NULL, ctx))
		{
			ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
			goto err;
		}
	}
	
	if (!BN_nnmod(u1, X, order, ctx))
	{
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	/*  if the signature is correct u1 is equal to sig->r */
	ret = (BN_ucmp(u1, sig->r) == 0);
err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	if (point)
		EC_POINT_free(point);
	return ret;
}
