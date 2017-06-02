/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include "modes_lcl.h"

#ifndef OPENSSL_NO_OCB

/*
 * Calculate the number of binary trailing zero's in any given number
 */
static u32 ocb_ntz(u64 n)
{
    u32 cnt = 0;

    /*
     * We do a right-to-left simple sequential search. This is surprisingly
     * efficient as the distribution of trailing zeros is not uniform,
     * e.g. the number of possible inputs with no trailing zeros is equal to
     * the number with 1 or more; the number with exactly 1 is equal to the
     * number with 2 or more, etc. Checking the last two bits covers 75% of
     * all numbers. Checking the last three covers 87.5%
     */
    while (!(n & 1)) {
        n >>= 1;
        cnt++;
    }
    return cnt;
}

/*
 * Shift a block of 16 bytes left by shift bits
 */
static void ocb_block_lshift(const unsigned char *in, size_t shift,
                             unsigned char *out)
{
    unsigned char shift_mask;
    int i;
    unsigned char mask[15];

    shift_mask = 0xff;
    shift_mask <<= (8 - shift);
    for (i = 15; i >= 0; i--) {
        if (i > 0) {
            mask[i - 1] = in[i] & shift_mask;
            mask[i - 1] >>= 8 - shift;
        }
        out[i] = in[i] << shift;

        if (i != 15) {
            out[i] ^= mask[i];
        }
    }
}

/*
 * Perform a "double" operation as per OCB spec
 */
static void ocb_double(OCB_BLOCK *in, OCB_BLOCK *out)
{
    unsigned char mask;

    /*
     * Calculate the mask based on the most significant bit. There are more
     * efficient ways to do this - but this way is constant time
     */
    mask = in->c[0] & 0x80;
    mask >>= 7;
    mask *= 135;

    ocb_block_lshift(in->c, 1, out->c);

    out->c[15] ^= mask;
}

/*
 * Perform an xor on in1 and in2 - each of len bytes. Store result in out
 */
static void ocb_block_xor(const unsigned char *in1,
                          const unsigned char *in2, size_t len,
                          unsigned char *out)
{
    size_t i;
    for (i = 0; i < len; i++) {
        out[i] = in1[i] ^ in2[i];
    }
}

/*
 * Lookup L_index in our lookup table. If we haven't already got it we need to
 * calculate it
 */
static OCB_BLOCK *ocb_lookup_l(OCB128_CONTEXT *ctx, size_t idx)
{
    size_t l_index = ctx->l_index;

    if (idx <= l_index) {
        return ctx->l + idx;
    }

    /* We don't have it - so calculate it */
    if (idx >= ctx->max_l_index) {
        void *tmp_ptr;
        /*
         * Each additional entry allows to process almost double as
         * much data, so that in linear world the table will need to
         * be expanded with smaller and smaller increments. Originally
         * it was doubling in size, which was a waste. Growing it
         * linearly is not formally optimal, but is simpler to implement.
         * We grow table by minimally required 4*n that would accommodate
         * the index.
         */
        ctx->max_l_index += (idx - ctx->max_l_index + 4) & ~3;
        tmp_ptr =
            OPENSSL_realloc(ctx->l, ctx->max_l_index * sizeof(OCB_BLOCK));
        if (tmp_ptr == NULL) /* prevent ctx->l from being clobbered */
            return NULL;
        ctx->l = tmp_ptr;
    }
    while (l_index < idx) {
        ocb_double(ctx->l + l_index, ctx->l + l_index + 1);
        l_index++;
    }
    ctx->l_index = l_index;

    return ctx->l + idx;
}

/*
 * Create a new OCB128_CONTEXT
 */
OCB128_CONTEXT *CRYPTO_ocb128_new(void *keyenc, void *keydec,
                                  block128_f encrypt, block128_f decrypt,
                                  ocb128_f stream)
{
    OCB128_CONTEXT *octx;
    int ret;

    if ((octx = OPENSSL_malloc(sizeof(*octx))) != NULL) {
        ret = CRYPTO_ocb128_init(octx, keyenc, keydec, encrypt, decrypt,
                                 stream);
        if (ret)
            return octx;
        OPENSSL_free(octx);
    }

    return NULL;
}

/*
 * Initialise an existing OCB128_CONTEXT
 */
int CRYPTO_ocb128_init(OCB128_CONTEXT *ctx, void *keyenc, void *keydec,
                       block128_f encrypt, block128_f decrypt,
                       ocb128_f stream)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->l_index = 0;
    ctx->max_l_index = 5;
    ctx->l = OPENSSL_malloc(ctx->max_l_index * 16);
    if (ctx->l == NULL)
        return 0;

    /*
     * We set both the encryption and decryption key schedules - decryption
     * needs both. Don't really need decryption schedule if only doing
     * encryption - but it simplifies things to take it anyway
     */
    ctx->encrypt = encrypt;
    ctx->decrypt = decrypt;
    ctx->stream = stream;
    ctx->keyenc = keyenc;
    ctx->keydec = keydec;

    /* L_* = ENCIPHER(K, zeros(128)) */
    ctx->encrypt(ctx->l_star.c, ctx->l_star.c, ctx->keyenc);

    /* L_$ = double(L_*) */
    ocb_double(&ctx->l_star, &ctx->l_dollar);

    /* L_0 = double(L_$) */
    ocb_double(&ctx->l_dollar, ctx->l);

    /* L_{i} = double(L_{i-1}) */
    ocb_double(ctx->l, ctx->l+1);
    ocb_double(ctx->l+1, ctx->l+2);
    ocb_double(ctx->l+2, ctx->l+3);
    ocb_double(ctx->l+3, ctx->l+4);
    ctx->l_index = 4;   /* enough to process up to 496 bytes */

    return 1;
}

/*
 * Copy an OCB128_CONTEXT object
 */
int CRYPTO_ocb128_copy_ctx(OCB128_CONTEXT *dest, OCB128_CONTEXT *src,
                           void *keyenc, void *keydec)
{
    memcpy(dest, src, sizeof(OCB128_CONTEXT));
    if (keyenc)
        dest->keyenc = keyenc;
    if (keydec)
        dest->keydec = keydec;
    if (src->l) {
        dest->l = OPENSSL_malloc(src->max_l_index * 16);
        if (dest->l == NULL)
            return 0;
        memcpy(dest->l, src->l, (src->l_index + 1) * 16);
    }
    return 1;
}

/*
 * Set the IV to be used for this operation. Must be 1 - 15 bytes.
 */
int CRYPTO_ocb128_setiv(OCB128_CONTEXT *ctx, const unsigned char *iv,
                        size_t len, size_t taglen)
{
    unsigned char ktop[16], tmp[16], mask;
    unsigned char stretch[24], nonce[16];
    size_t bottom, shift;

    /*
     * Spec says IV is 120 bits or fewer - it allows non byte aligned lengths.
     * We don't support this at this stage
     */
    if ((len > 15) || (len < 1) || (taglen > 16) || (taglen < 1)) {
        return -1;
    }

    /* Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N */
    nonce[0] = ((taglen * 8) % 128) << 1;
    memset(nonce + 1, 0, 15);
    memcpy(nonce + 16 - len, iv, len);
    nonce[15 - len] |= 1;

    /* Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6)) */
    memcpy(tmp, nonce, 16);
    tmp[15] &= 0xc0;
    ctx->encrypt(tmp, ktop, ctx->keyenc);

    /* Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]) */
    memcpy(stretch, ktop, 16);
    ocb_block_xor(ktop, ktop + 1, 8, stretch + 16);

    /* bottom = str2num(Nonce[123..128]) */
    bottom = nonce[15] & 0x3f;

    /* Offset_0 = Stretch[1+bottom..128+bottom] */
    shift = bottom % 8;
    ocb_block_lshift(stretch + (bottom / 8), shift, ctx->offset.c);
    mask = 0xff;
    mask <<= 8 - shift;
    ctx->offset.c[15] |=
        (*(stretch + (bottom / 8) + 16) & mask) >> (8 - shift);

    return 1;
}

/*
 * Provide any AAD. This can be called multiple times. Only the final time can
 * have a partial block
 */
int CRYPTO_ocb128_aad(OCB128_CONTEXT *ctx, const unsigned char *aad,
                      size_t len)
{
    u64 i, all_num_blocks;
    size_t num_blocks, last_len;
    OCB_BLOCK tmp1;
    OCB_BLOCK tmp2;

    /* Calculate the number of blocks of AAD provided now, and so far */
    num_blocks = len / 16;
    all_num_blocks = num_blocks + ctx->blocks_hashed;

    /* Loop through all full blocks of AAD */
    for (i = ctx->blocks_hashed + 1; i <= all_num_blocks; i++) {
        OCB_BLOCK *lookup;
        OCB_BLOCK *aad_block;

        /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
        lookup = ocb_lookup_l(ctx, ocb_ntz(i));
        if (lookup == NULL)
            return 0;
        ocb_block16_xor(&ctx->offset_aad, lookup, &ctx->offset_aad);

        /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i) */
        aad_block = (OCB_BLOCK *)(aad + ((i - ctx->blocks_hashed - 1) * 16));
        ocb_block16_xor(&ctx->offset_aad, aad_block, &tmp1);
        ctx->encrypt(tmp1.c, tmp2.c, ctx->keyenc);
        ocb_block16_xor(&ctx->sum, &tmp2, &ctx->sum);
    }

    /*
     * Check if we have any partial blocks left over. This is only valid in the
     * last call to this function
     */
    last_len = len % 16;

    if (last_len > 0) {
        /* Offset_* = Offset_m xor L_* */
        ocb_block16_xor(&ctx->offset_aad, &ctx->l_star, &ctx->offset_aad);

        /* CipherInput = (A_* || 1 || zeros(127-bitlen(A_*))) xor Offset_* */
        memset(&tmp1, 0, 16);
        memcpy(&tmp1, aad + (num_blocks * 16), last_len);
        ((unsigned char *)&tmp1)[last_len] = 0x80;
        ocb_block16_xor(&ctx->offset_aad, &tmp1, &tmp2);

        /* Sum = Sum_m xor ENCIPHER(K, CipherInput) */
        ctx->encrypt(tmp2.c, tmp1.c, ctx->keyenc);
        ocb_block16_xor(&ctx->sum, &tmp1, &ctx->sum);
    }

    ctx->blocks_hashed = all_num_blocks;

    return 1;
}

/*
 * Provide any data to be encrypted. This can be called multiple times. Only
 * the final time can have a partial block
 */
int CRYPTO_ocb128_encrypt(OCB128_CONTEXT *ctx,
                          const unsigned char *in, unsigned char *out,
                          size_t len)
{
    u64 i, all_num_blocks;
    size_t num_blocks, last_len;
    OCB_BLOCK tmp1;
    OCB_BLOCK tmp2;
    OCB_BLOCK pad;

    /*
     * Calculate the number of blocks of data to be encrypted provided now, and
     * so far
     */
    num_blocks = len / 16;
    all_num_blocks = num_blocks + ctx->blocks_processed;

    if (num_blocks && all_num_blocks == (size_t)all_num_blocks
        && ctx->stream != NULL) {
        size_t max_idx = 0, top = (size_t)all_num_blocks;

        /*
         * See how many L_{i} entries we need to process data at hand
         * and pre-compute missing entries in the table [if any]...
         */
        while (top >>= 1)
            max_idx++;
        if (ocb_lookup_l(ctx, max_idx) == NULL)
            return 0;

        ctx->stream(in, out, num_blocks, ctx->keyenc,
                    (size_t)ctx->blocks_processed + 1, ctx->offset.c,
                    (const unsigned char (*)[16])ctx->l, ctx->checksum.c);
    } else {
        /* Loop through all full blocks to be encrypted */
        for (i = ctx->blocks_processed + 1; i <= all_num_blocks; i++) {
            OCB_BLOCK *lookup;
            OCB_BLOCK *inblock;
            OCB_BLOCK *outblock;

            /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
            lookup = ocb_lookup_l(ctx, ocb_ntz(i));
            if (lookup == NULL)
                return 0;
            ocb_block16_xor(&ctx->offset, lookup, &ctx->offset);

            /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i) */
            inblock =
                (OCB_BLOCK *)(in + ((i - ctx->blocks_processed - 1) * 16));
            ocb_block16_xor_misaligned(&ctx->offset, inblock, &tmp1);
            /* Checksum_i = Checksum_{i-1} xor P_i */
            ocb_block16_xor_misaligned(&ctx->checksum, inblock, &ctx->checksum);
            ctx->encrypt(tmp1.c, tmp2.c, ctx->keyenc);
            outblock =
                (OCB_BLOCK *)(out + ((i - ctx->blocks_processed - 1) * 16));
            ocb_block16_xor_misaligned(&ctx->offset, &tmp2, outblock);
        }
    }

    /*
     * Check if we have any partial blocks left over. This is only valid in the
     * last call to this function
     */
    last_len = len % 16;

    if (last_len > 0) {
        /* Offset_* = Offset_m xor L_* */
        ocb_block16_xor(&ctx->offset, &ctx->l_star, &ctx->offset);

        /* Pad = ENCIPHER(K, Offset_*) */
        ctx->encrypt(ctx->offset.c, pad.c, ctx->keyenc);

        /* C_* = P_* xor Pad[1..bitlen(P_*)] */
        ocb_block_xor(in + (len / 16) * 16, (unsigned char *)&pad, last_len,
                      out + (num_blocks * 16));

        /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
        memset(&tmp1, 0, 16);
        memcpy(&tmp1, in + (len / 16) * 16, last_len);
        ((unsigned char *)(&tmp1))[last_len] = 0x80;
        ocb_block16_xor(&ctx->checksum, &tmp1, &ctx->checksum);
    }

    ctx->blocks_processed = all_num_blocks;

    return 1;
}

/*
 * Provide any data to be decrypted. This can be called multiple times. Only
 * the final time can have a partial block
 */
int CRYPTO_ocb128_decrypt(OCB128_CONTEXT *ctx,
                          const unsigned char *in, unsigned char *out,
                          size_t len)
{
    u64 i, all_num_blocks;
    size_t num_blocks, last_len;
    OCB_BLOCK tmp1;
    OCB_BLOCK tmp2;
    OCB_BLOCK pad;

    /*
     * Calculate the number of blocks of data to be decrypted provided now, and
     * so far
     */
    num_blocks = len / 16;
    all_num_blocks = num_blocks + ctx->blocks_processed;

    if (num_blocks && all_num_blocks == (size_t)all_num_blocks
        && ctx->stream != NULL) {
        size_t max_idx = 0, top = (size_t)all_num_blocks;

        /*
         * See how many L_{i} entries we need to process data at hand
         * and pre-compute missing entries in the table [if any]...
         */
        while (top >>= 1)
            max_idx++;
        if (ocb_lookup_l(ctx, max_idx) == NULL)
            return 0;

        ctx->stream(in, out, num_blocks, ctx->keydec,
                    (size_t)ctx->blocks_processed + 1, ctx->offset.c,
                    (const unsigned char (*)[16])ctx->l, ctx->checksum.c);
    } else {
        /* Loop through all full blocks to be decrypted */
        for (i = ctx->blocks_processed + 1; i <= all_num_blocks; i++) {
            OCB_BLOCK *inblock;
            OCB_BLOCK *outblock;

            /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
            OCB_BLOCK *lookup = ocb_lookup_l(ctx, ocb_ntz(i));
            if (lookup == NULL)
                return 0;
            ocb_block16_xor(&ctx->offset, lookup, &ctx->offset);

            /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i) */
            inblock =
                (OCB_BLOCK *)(in + ((i - ctx->blocks_processed - 1) * 16));
            ocb_block16_xor_misaligned(&ctx->offset, inblock, &tmp1);
            ctx->decrypt(tmp1.c, tmp2.c, ctx->keydec);
            outblock =
                (OCB_BLOCK *)(out + ((i - ctx->blocks_processed - 1) * 16));
            ocb_block16_xor_misaligned(&ctx->offset, &tmp2, outblock);

            /* Checksum_i = Checksum_{i-1} xor P_i */
            ocb_block16_xor_misaligned(&ctx->checksum, outblock, &ctx->checksum);
        }
    }

    /*
     * Check if we have any partial blocks left over. This is only valid in the
     * last call to this function
     */
    last_len = len % 16;

    if (last_len > 0) {
        /* Offset_* = Offset_m xor L_* */
        ocb_block16_xor(&ctx->offset, &ctx->l_star, &ctx->offset);

        /* Pad = ENCIPHER(K, Offset_*) */
        ctx->encrypt(ctx->offset.c, pad.c, ctx->keyenc);

        /* P_* = C_* xor Pad[1..bitlen(C_*)] */
        ocb_block_xor(in + (len / 16) * 16, (unsigned char *)&pad, last_len,
                      out + (num_blocks * 16));

        /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
        memset(&tmp1, 0, 16);
        memcpy(&tmp1, out + (len / 16) * 16, last_len);
        ((unsigned char *)(&tmp1))[last_len] = 0x80;
        ocb_block16_xor(&ctx->checksum, &tmp1, &ctx->checksum);
    }

    ctx->blocks_processed = all_num_blocks;

    return 1;
}

/*
 * Calculate the tag and verify it against the supplied tag
 */
int CRYPTO_ocb128_finish(OCB128_CONTEXT *ctx, const unsigned char *tag,
                         size_t len)
{
    OCB_BLOCK tmp1, tmp2;

    /*
     * Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
     */
    ocb_block16_xor(&ctx->checksum, &ctx->offset, &tmp1);
    ocb_block16_xor(&tmp1, &ctx->l_dollar, &tmp2);
    ctx->encrypt(tmp2.c, tmp1.c, ctx->keyenc);
    ocb_block16_xor(&tmp1, &ctx->sum, &ctx->tag);

    if (len > 16 || len < 1) {
        return -1;
    }

    /* Compare the tag if we've been given one */
    if (tag)
        return CRYPTO_memcmp(&ctx->tag, tag, len);
    else
        return -1;
}

/*
 * Retrieve the calculated tag
 */
int CRYPTO_ocb128_tag(OCB128_CONTEXT *ctx, unsigned char *tag, size_t len)
{
    if (len > 16 || len < 1) {
        return -1;
    }

    /* Calculate the tag */
    CRYPTO_ocb128_finish(ctx, NULL, 0);

    /* Copy the tag into the supplied buffer */
    memcpy(tag, &ctx->tag, len);

    return 1;
}

/*
 * Release all resources
 */
void CRYPTO_ocb128_cleanup(OCB128_CONTEXT *ctx)
{
    if (ctx) {
        OPENSSL_clear_free(ctx->l, ctx->max_l_index * 16);
        OPENSSL_cleanse(ctx, sizeof(*ctx));
    }
}

#endif                          /* OPENSSL_NO_OCB */
