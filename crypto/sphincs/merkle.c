/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#include "merkle.h"

#include <stdlib.h>

int merkle_base_address (const struct address *address, struct address *base_address) {
    int index = address->index & (MERKLE_hhh - 1);
    if (base_address != NULL) {
        base_address->layer = address->layer;
        base_address->index = address->index - index;
    }
    return index;
}

int merkle_genpk (const struct hash *key, const struct address *address, struct merkle_pk *pk) {
    struct address base_address;
    struct hash *buf;
    struct wots_sk wsk;
    struct lwots_pk wpk;
    int j;

    merkle_base_address (address, &base_address);

    buf = merkle_alloc_buf (MERKLE_h);
    if (buf == NULL) return GRAVITY_ERR_ALLOC;

    /* Leaves */
    for (j = 0; j < MERKLE_hhh; ++j) {
        wots_gensk (key, &base_address, &wsk);
        lwots_genpk (&wsk, &wpk);
        hashcpy (&buf[j], &wpk.k);

        ++base_address.index;
    }

    /* Merkle tree */
    merkle_compress_all (buf, MERKLE_h, &pk->k);

    merkle_free_buf (buf);
    return GRAVITY_OK;
}

int merkle_sign (const struct hash *key,
                 const struct address *address,
                 struct merkle_sign *sign,
                 const struct hash *msg,
                 struct merkle_pk *pk) {
    struct address base_address;
    struct hash *buf;
    struct wots_sk wsk;
    struct lwots_pk wpk;
    int index;
    int j;

    index = merkle_base_address (address, &base_address);

    buf = merkle_alloc_buf (MERKLE_h);
    if (buf == NULL) return GRAVITY_ERR_ALLOC;

    /* Leaves */
    for (j = 0; j < MERKLE_hhh; ++j) {
        wots_gensk (key, &base_address, &wsk);
        lwots_genpk (&wsk, &wpk);
        hashcpy (&buf[j], &wpk.k);

        ++base_address.index;

        /* WOTS */
        if (j == index) wots_sign (&wsk, &sign->wots, msg);
    }

    /* Merkle tree */
    merkle_gen_auth (buf, MERKLE_h, sign->auth, index, pk == NULL ? NULL : &pk->k);

    merkle_free_buf (buf);
    return GRAVITY_OK;
}

void merkle_extract (struct merkle_pk *pk,
                     const struct address *address,
                     const struct merkle_sign *sign,
                     const struct hash *msg) {
    struct lwots_pk wpk;
    int index = merkle_base_address (address, NULL);

    /* WOTS */
    lwots_extract (&wpk, &sign->wots, msg);

    /* Auth path */
    merkle_compress_auth (&wpk.k, index, sign->auth, MERKLE_h);
    hashcpy (&pk->k, &wpk.k);
}


/* Helper functions */
/* Alloc/free a buffer large enough to store leaves and compress them */
struct hash *merkle_alloc_buf (int height) {
    int n = 1 << height;
    return malloc (2 * n * HASH_SIZE);
}

void merkle_free_buf (struct hash *buf) {
    /* TODO: wipe buffer? */
    free (buf);
}

/* Compress leaves from level height until root */
void merkle_compress_all (struct hash *buf, int height, struct hash *root) {
    int n = 1 << height;
    struct hash *src = &buf[n];
    struct hash *dst = &buf[0];
    struct hash *tmp;
    int l;

    for (l = 0; l < height; ++l) {
        /* Swap buffers */
        hashswap (src, dst, tmp);
        n >>= 1;

        /* Compute all hashes at current layer */
        hash_compress_pairs (dst, src, n);
    }

    hashcpy (root, dst);
}

/* Compute authentication path */
void merkle_gen_auth (struct hash *buf, int height, struct hash *auth, int index, struct hash *root) {
    int n = 1 << height;
    struct hash *src = &buf[n];
    struct hash *dst = &buf[0];
    struct hash *tmp;
    int l, sibling;

    for (l = 0; l < height; ++l) {
        /* Copy auth path */
        sibling = index ^ 1;
        hashcpy (&auth[l], &dst[sibling]);
        index >>= 1;

        /* Swap buffers */
        hashswap (src, dst, tmp);
        n >>= 1;

        /* Compute all hashes at current layer */
        hash_compress_pairs (dst, src, n);
    }

    /* Public key */
    if (root != NULL) hashcpy (root, dst);
}

/* Compress node with its auth path on height_diff levels */
int merkle_compress_auth (struct hash *node, int index, const struct hash *auth, int height_diff) {
    struct hash buf[2];
    int l;

    for (l = 0; l < height_diff; ++l) {
        if (index % 2 == 0) {
            hashcpy (&buf[0], node);
            hashcpy (&buf[1], &auth[l]);
        } else {
            hashcpy (&buf[0], &auth[l]);
            hashcpy (&buf[1], node);
        }

        hash_2N_to_N (node, buf);

        index >>= 1;
    }

    return index;
}

void merkle_gen_octopus (struct hash *buf,
                         int height,
                         struct hash *octopus,
                         int *octolen,
                         struct hash *root,
                         int *indices,
                         int count) {
    int n = 1 << height;
    struct hash *src = &buf[n];
    struct hash *dst = &buf[0];
    struct hash *tmp;
    int i, j, l;
    int len = 0;
    int index, sibling;

    for (l = 0; l < height; ++l) {
        /* Copy auth octopus */
        for (i = 0, j = 0; i < count; ++i, ++j) {
            index = indices[i];
            sibling = index ^ 1;

            /* Check redundancy with sibling */
            if (i + 1 < count && indices[i + 1] == sibling)
                ++i;
            else
                hashcpy (&octopus[len++], &dst[sibling]);

            indices[j] = indices[i] >> 1;
        }
        /* Update count of non-redundant nodes */
        count = j;

        /* Swap buffers */
        hashswap (src, dst, tmp);
        n >>= 1;

        /* Compute all hashes at current layer */
        hash_compress_pairs (dst, src, n);
    }

    hashcpy (root, dst);
    *octolen = len;
}

int merkle_compress_octopus (struct hash *nodes,
                             int height,
                             const struct hash *octopus,
                             int octolen,
                             int *indices,
                             int count) {
    struct hash buf[2];
    int i, j, l;
    int len = 0;
    int index;

    for (l = 0; l < height; ++l) {
        for (i = 0, j = 0; i < count; ++i, ++j) {
            /* Select 2 values to merge */
            index = indices[i];
            if (index % 2 == 0) {
                hashcpy (&buf[0], &nodes[i]);

                if (i + 1 < count && indices[i + 1] == index + 1) {
                    ++i;
                    hashcpy (&buf[1], &nodes[i]);
                } else {
                    if (len == octolen) return GRAVITY_ERR_VERIF;
                    hashcpy (&buf[1], &octopus[len++]);
                }
            } else {
                if (len == octolen) return GRAVITY_ERR_VERIF;
                hashcpy (&buf[0], &octopus[len++]);
                hashcpy (&buf[1], &nodes[i]);
            }

            /* Hash values */
            hash_2N_to_N (&nodes[j], buf);

            indices[j] = indices[i] >> 1;
        }

        /* Update count of non-redundant nodes */
        count = j;
    }

    /* Check len */
    if (len != octolen) return GRAVITY_ERR_VERIF;

    return GRAVITY_OK;
}
