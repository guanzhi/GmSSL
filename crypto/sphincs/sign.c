/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#include "gravity.h"
#include "randombytes.h"


int crypto_sign_keypair (unsigned char *pk, unsigned char *sk) {

    struct gravity_sk sk_str;
    struct gravity_pk pk_str;

    if (!pk || !sk) return -1;

    randombytes (sk_str.seed.h, HASH_SIZE);
    randombytes (sk_str.salt.h, HASH_SIZE);

    gravity_gensk (&sk_str);

    memcpy (sk, (void *)&sk_str, sizeof (struct gravity_sk));

    gravity_genpk (&sk_str, &pk_str);

    memcpy (pk, pk_str.k.h, HASH_SIZE);

    return 0;
}

int crypto_sign (unsigned char *sm,
                 unsigned long long *smlen,
                 const unsigned char *m,
                 unsigned long long mlen,
                 const unsigned char *sk) {

    struct gravity_sk sk_str;
    struct hash msg;
    struct gravity_sign sig;
    int ret;

    if (!sm || !smlen || !m || !sk) return -1;

    hash_to_N (&msg, m, mlen);

    memcpy ((void *)&sk_str, sk, sizeof (struct gravity_sk));

    memset ((uint8_t *)(&sig), 0, sizeof (struct gravity_sign));

    ret = gravity_sign (&sk_str, &sig, &msg);

    if (ret != GRAVITY_OK) return ret;

    memcpy (sm + mlen, (uint8_t *)(&sig), sizeof (struct gravity_sign));

    memmove (sm, m, mlen);
    *smlen = mlen + sizeof (struct gravity_sign);

    return 0;
}

int crypto_sign_open (unsigned char *m,
                      unsigned long long *mlen,
                      const unsigned char *sm,
                      unsigned long long smlen,
                      const unsigned char *pk) {

    struct gravity_pk pk_str;
    struct hash msg;
    struct gravity_sign sig;

    if (!m || !mlen || !sm || !pk) return -1;

    if (smlen < sizeof (struct gravity_sign)) return -2;

    *mlen = smlen - sizeof (struct gravity_sign);

    memcpy ((void *)(&pk_str), pk, HASH_SIZE);

    memcpy ((void *)&sig, sm + *mlen, sizeof (struct gravity_sign));

    memcpy (m, sm, *mlen);

    hash_to_N (&msg, m, *mlen);

    return gravity_verify (&pk_str, &sig, &msg);
}
