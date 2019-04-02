/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#include "ltree.h"

void ltree (struct hash *buf, int count, struct hash *root) {
    struct hash *src = &buf[count];
    struct hash *dst = &buf[0];
    struct hash *tmp;
    int newcount;

    while (count > 1) {
        /* Swap buffers */
        hashswap (src, dst, tmp);

        /* Compute all hashes at current layer */
        newcount = count >> 1;
        hash_compress_pairs (dst, src, newcount);
        if (count & 1) {
            hashcpy (&dst[newcount], &src[count - 1]);
            ++newcount;
        }

        count = newcount;
    }

    hashcpy (root, dst);
}
