/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#include "wots.h"
#include "aes.h"

#include "ltree.h"

void wots_chain (const struct hash *src, struct hash *dst, int count) {
    hash_N_to_N_chain (dst, src, count);
}

/* Naive WOTS without L-tree nor masks */
void wots_gensk (const struct hash *key, const struct address *address, struct wots_sk *sk) {
    uint8_t iv[16];

    iv[0] = (address->index >> 56) & 0xFF;
    iv[1] = (address->index >> 48) & 0xFF;
    iv[2] = (address->index >> 40) & 0xFF;
    iv[3] = (address->index >> 32) & 0xFF;
    iv[4] = (address->index >> 24) & 0xFF;
    iv[5] = (address->index >> 16) & 0xFF;
    iv[6] = (address->index >> 8) & 0xFF;
    iv[7] = address->index & 0xFF;

    iv[8] = (address->layer >> 24) & 0xFF;
    iv[9] = (address->layer >> 16) & 0xFF;
    iv[10] = (address->layer >> 8) & 0xFF;
    iv[11] = address->layer & 0xFF;

    /* Counter */
    iv[12] = 0;
    iv[13] = 0;
    iv[14] = 0;
    iv[15] = 0;
    aesctr256 (sk->k->h, key->h, iv, WOTS_ell * HASH_SIZE);
}

void wots_sign (const struct wots_sk *sk, struct wots_sign *sign, const struct hash *msg) {
    int checksum = 0;
    int i;

    for (i = 0; i < WOTS_ell1; ++i) {
        uint8_t v = msg->h[i / 2];
        int a = (v >> 4) & 15;
        int b = v & 15;
        checksum += (WOTS_w - 1 - a) + (WOTS_w - 1 - b);

        wots_chain (&sk->k[i], &sign->s[i], a);
        ++i;
        wots_chain (&sk->k[i], &sign->s[i], b);
    }

    /* Checksum values */
    for (i = WOTS_ell1; i < WOTS_ell; ++i) {
        wots_chain (&sk->k[i], &sign->s[i], checksum & 15);
        checksum >>= 4;
    }
}


/* WOTS with L-tree and without masks */
void lwots_ltree (const struct wots_pk *pk, struct lwots_pk *root) {
    struct hash buf[2 * WOTS_ell];

    hashcpyN (buf, pk->k, WOTS_ell);
    ltree (buf, WOTS_ell, &root->k);
}

void lwots_genpk (const struct wots_sk *sk, struct lwots_pk *pk) {
    struct wots_pk tmp;

    hash_parallel_chains (tmp.k, sk->k, WOTS_ell, WOTS_w - 1);
    lwots_ltree (&tmp, pk);
}

void lwots_extract (struct lwots_pk *pk, const struct wots_sign *sign, const struct hash *msg) {
    struct wots_pk tmp;
    int i;
    int checksum = 0;

    for (i = 0; i < WOTS_ell1; ++i) {
        uint8_t v = msg->h[i / 2];
        int a = (v >> 4) & 15;
        int b = v & 15;
        checksum += (WOTS_w - 1 - a) + (WOTS_w - 1 - b);

        wots_chain (&sign->s[i], &tmp.k[i], WOTS_w - 1 - a);
        ++i;
        wots_chain (&sign->s[i], &tmp.k[i], WOTS_w - 1 - b);
    }

    /* Checksum values */
    for (i = WOTS_ell1; i < WOTS_ell; ++i) {
        wots_chain (&sign->s[i], &tmp.k[i], WOTS_w - 1 - (checksum & 15));
        checksum >>= 4;
    }

    /* L-tree */
    lwots_ltree (&tmp, pk);
}
