/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Portions of this software developed by SUN MICROSYSTEMS, INC.,
 * and contributed to the OpenSSL project.
 */

#include <openssl/err.h>

#include "ec_lcl.h"

const EC_METHOD *EC_GFp_mont_method(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_DEFAULT_OCT,
        NID_X9_62_prime_field,
        ec_GFp_mont_group_init,
        ec_GFp_mont_group_finish,
        ec_GFp_mont_group_clear_finish,
        ec_GFp_mont_group_copy,
        ec_GFp_mont_group_set_curve,
        ec_GFp_simple_group_get_curve,
        ec_GFp_simple_group_get_degree,
        ec_group_simple_order_bits,
        ec_GFp_simple_group_check_discriminant,
        ec_GFp_simple_point_init,
        ec_GFp_simple_point_finish,
        ec_GFp_simple_point_clear_finish,
        ec_GFp_simple_point_copy,
        ec_GFp_simple_point_set_to_infinity,
        ec_GFp_simple_set_Jprojective_coordinates_GFp,
        ec_GFp_simple_get_Jprojective_coordinates_GFp,
        ec_GFp_simple_point_set_affine_coordinates,
        ec_GFp_simple_point_get_affine_coordinates,
        0, 0, 0,
        ec_GFp_simple_add,
        ec_GFp_simple_dbl,
        ec_GFp_simple_invert,
        ec_GFp_simple_is_at_infinity,
        ec_GFp_simple_is_on_curve,
        ec_GFp_simple_cmp,
        ec_GFp_simple_make_affine,
        ec_GFp_simple_points_make_affine,
        0 /* mul */ ,
        0 /* precompute_mult */ ,
        0 /* have_precompute_mult */ ,
        ec_GFp_mont_field_mul,
        ec_GFp_mont_field_sqr,
        0 /* field_div */ ,
        ec_GFp_mont_field_encode,
        ec_GFp_mont_field_decode,
        ec_GFp_mont_field_set_to_one,
        ec_key_simple_priv2oct,
        ec_key_simple_oct2priv,
        0, /* set private */
        ec_key_simple_generate_key,
        ec_key_simple_check_key,
        ec_key_simple_generate_public_key,
        0, /* keycopy */
        0, /* keyfinish */
        ecdh_simple_compute_key
    };

    return &ret;
}

int ec_GFp_mont_group_init(EC_GROUP *group)
{
    int ok;

    ok = ec_GFp_simple_group_init(group);
    group->field_data1 = NULL;
    group->field_data2 = NULL;
    return ok;
}

void ec_GFp_mont_group_finish(EC_GROUP *group)
{
    BN_MONT_CTX_free(group->field_data1);
    group->field_data1 = NULL;
    BN_free(group->field_data2);
    group->field_data2 = NULL;
    ec_GFp_simple_group_finish(group);
}

void ec_GFp_mont_group_clear_finish(EC_GROUP *group)
{
    BN_MONT_CTX_free(group->field_data1);
    group->field_data1 = NULL;
    BN_clear_free(group->field_data2);
    group->field_data2 = NULL;
    ec_GFp_simple_group_clear_finish(group);
}

int ec_GFp_mont_group_copy(EC_GROUP *dest, const EC_GROUP *src)
{
    BN_MONT_CTX_free(dest->field_data1);
    dest->field_data1 = NULL;
    BN_clear_free(dest->field_data2);
    dest->field_data2 = NULL;

    if (!ec_GFp_simple_group_copy(dest, src))
        return 0;

    if (src->field_data1 != NULL) {
        dest->field_data1 = BN_MONT_CTX_new();
        if (dest->field_data1 == NULL)
            return 0;
        if (!BN_MONT_CTX_copy(dest->field_data1, src->field_data1))
            goto err;
    }
    if (src->field_data2 != NULL) {
        dest->field_data2 = BN_dup(src->field_data2);
        if (dest->field_data2 == NULL)
            goto err;
    }

    return 1;

 err:
    BN_MONT_CTX_free(dest->field_data1);
    dest->field_data1 = NULL;
    return 0;
}

int ec_GFp_mont_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *one = NULL;
    int ret = 0;

    BN_MONT_CTX_free(group->field_data1);
    group->field_data1 = NULL;
    BN_free(group->field_data2);
    group->field_data2 = NULL;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            return 0;
    }

    mont = BN_MONT_CTX_new();
    if (mont == NULL)
        goto err;
    if (!BN_MONT_CTX_set(mont, p, ctx)) {
        ECerr(EC_F_EC_GFP_MONT_GROUP_SET_CURVE, ERR_R_BN_LIB);
        goto err;
    }
    one = BN_new();
    if (one == NULL)
        goto err;
    if (!BN_to_montgomery(one, BN_value_one(), mont, ctx))
        goto err;

    group->field_data1 = mont;
    mont = NULL;
    group->field_data2 = one;
    one = NULL;

    ret = ec_GFp_simple_group_set_curve(group, p, a, b, ctx);

    if (!ret) {
        BN_MONT_CTX_free(group->field_data1);
        group->field_data1 = NULL;
        BN_free(group->field_data2);
        group->field_data2 = NULL;
    }

 err:
    BN_free(one);
    BN_CTX_free(new_ctx);
    BN_MONT_CTX_free(mont);
    return ret;
}

int ec_GFp_mont_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
                          const BIGNUM *b, BN_CTX *ctx)
{
    if (group->field_data1 == NULL) {
        ECerr(EC_F_EC_GFP_MONT_FIELD_MUL, EC_R_NOT_INITIALIZED);
        return 0;
    }

    return BN_mod_mul_montgomery(r, a, b, group->field_data1, ctx);
}

int ec_GFp_mont_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
                          BN_CTX *ctx)
{
    if (group->field_data1 == NULL) {
        ECerr(EC_F_EC_GFP_MONT_FIELD_SQR, EC_R_NOT_INITIALIZED);
        return 0;
    }

    return BN_mod_mul_montgomery(r, a, a, group->field_data1, ctx);
}

int ec_GFp_mont_field_encode(const EC_GROUP *group, BIGNUM *r,
                             const BIGNUM *a, BN_CTX *ctx)
{
    if (group->field_data1 == NULL) {
        ECerr(EC_F_EC_GFP_MONT_FIELD_ENCODE, EC_R_NOT_INITIALIZED);
        return 0;
    }

    return BN_to_montgomery(r, a, (BN_MONT_CTX *)group->field_data1, ctx);
}

int ec_GFp_mont_field_decode(const EC_GROUP *group, BIGNUM *r,
                             const BIGNUM *a, BN_CTX *ctx)
{
    if (group->field_data1 == NULL) {
        ECerr(EC_F_EC_GFP_MONT_FIELD_DECODE, EC_R_NOT_INITIALIZED);
        return 0;
    }

    return BN_from_montgomery(r, a, group->field_data1, ctx);
}

int ec_GFp_mont_field_set_to_one(const EC_GROUP *group, BIGNUM *r,
                                 BN_CTX *ctx)
{
    if (group->field_data2 == NULL) {
        ECerr(EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE, EC_R_NOT_INITIALIZED);
        return 0;
    }

    if (!BN_copy(r, group->field_data2))
        return 0;
    return 1;
}
