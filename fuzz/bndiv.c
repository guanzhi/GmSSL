/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Confirm that if (d, r) = a / b, then b * d + r == a, and that sign(d) ==
 * sign(a), and 0 <= r <= b
 */

#include <stdio.h>
#include <openssl/bn.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv) {
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len) {
    static BN_CTX *ctx;
    static BIGNUM *b1;
    static BIGNUM *b2;
    static BIGNUM *b3;
    static BIGNUM *b4;
    static BIGNUM *b5;
    int success = 0;
    size_t l1 = 0, l2 = 0;
    /* s1 and s2 will be the signs for b1 and b2. */
    int s1 = 0, s2 = 0;

    if (ctx == NULL) {
        b1 = BN_new();
        b2 = BN_new();
        b3 = BN_new();
        b4 = BN_new();
        b5 = BN_new();
        ctx = BN_CTX_new();
    }
    /* We are going to split the buffer in two, sizes l1 and l2, giving b1 and
     * b2.
     */
    if (len > 0) {
        --len;
        /* Use first byte to divide the remaining buffer into 3Fths. I admit
         * this disallows some number sizes. If it matters, better ideas are
         * welcome (Ben).
         */
        l1 = ((buf[0] & 0x3f) * len) / 0x3f;
        s1 = buf[0] & 0x40;
        s2 = buf[0] & 0x80;
        ++buf;
        l2 = len - l1;
    }
    OPENSSL_assert(BN_bin2bn(buf, l1, b1) == b1);
    BN_set_negative(b1, s1);
    OPENSSL_assert(BN_bin2bn(buf + l1, l2, b2) == b2);
    BN_set_negative(b2, s2);

    /* divide by 0 is an error */
    if (BN_is_zero(b2)) {
        success = 1;
        goto done;
    }

    OPENSSL_assert(BN_div(b3, b4, b1, b2, ctx));
    if (BN_is_zero(b1))
        success = BN_is_zero(b3) && BN_is_zero(b4);
    else if (BN_is_negative(b1))
        success = (BN_is_negative(b3) != BN_is_negative(b2) || BN_is_zero(b3))
            && (BN_is_negative(b4) || BN_is_zero(b4));
    else
        success = (BN_is_negative(b3) == BN_is_negative(b2)  || BN_is_zero(b3))
            && (!BN_is_negative(b4) || BN_is_zero(b4));
    OPENSSL_assert(BN_mul(b5, b3, b2, ctx));
    OPENSSL_assert(BN_add(b5, b5, b4));

    success = success && BN_cmp(b5, b1) == 0;
    if (!success) {
        BN_print_fp(stdout, b1);
        putchar('\n');
        BN_print_fp(stdout, b2);
        putchar('\n');
        BN_print_fp(stdout, b3);
        putchar('\n');
        BN_print_fp(stdout, b4);
        putchar('\n');
        BN_print_fp(stdout, b5);
        putchar('\n');
        printf("%d %d %d %d %d %d %d\n", BN_is_negative(b1),
               BN_is_negative(b2),
               BN_is_negative(b3), BN_is_negative(b4), BN_is_zero(b4),
               BN_is_negative(b3) != BN_is_negative(b2)
               && (BN_is_negative(b4) || BN_is_zero(b4)),
               BN_cmp(b5, b1));
        puts("----\n");
    }

 done:
    OPENSSL_assert(success);

    return 0;
}
