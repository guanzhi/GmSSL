/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#include "batch.h"

#include "merkle.h"

int batch_init (struct batch_buf *buf) {
    buf->count = 0;
    return GRAVITY_OK;
}

int batch_append (struct batch_buf *buf, const uint8_t *msg, uint64_t len, uint32_t *index) {
    if (buf->count == MAX_BATCH_COUNT) return GRAVITY_ERR_BATCH;

    /* TODO: randomize this hash? */
    hash_to_N (&buf->buf[buf->count], msg, len);

    *index = buf->count;
    ++buf->count;

    return GRAVITY_OK;
}

int batch_group (struct batch_group *group, struct batch_buf *buf) {
    int height = LOG_MAX_BATCH_COUNT;
    int n = 1 << height;
    int offset = n - 1;

    struct hash *src;
    struct hash *dst;
    uint32_t count;
    int i;

    /* Check batch count */
    count = buf->count;
    if (count == 0) return GRAVITY_ERR_BATCH;
    group->count = count;

    /* Leaves */
    dst = &group->tree[offset];

    hashcpyN (dst, buf->buf, count);
    for (i = count; i < n; ++i) hashcpy (&dst[i], &buf->buf[0]);

    /* Compress until root */
    while (height > 0) {
        offset >>= 1;
        --height;

        src = dst;
        dst = &group->tree[offset];
        hash_compress_pairs (dst, src, 1 << height);
    }

    return GRAVITY_OK;
}

int batch_extract (const struct batch_group *group, struct batch_auth *auth, uint32_t index) {
    int height = LOG_MAX_BATCH_COUNT;
    int n = 1 << height;
    int offset = n - 1;

    uint32_t count;
    int i, sibling;

    /* Check batch count */
    count = group->count;
    if (index >= count) return GRAVITY_ERR_BATCH;

    /* Convert row index into tree index */
    auth->index = offset + index;

    /* Copy auth path */
    for (i = 0; i < height; ++i) {
        sibling = index ^ 1;
        hashcpy (&auth->auth[i], &group->tree[offset + sibling]);
        index >>= 1;
        offset >>= 1;
    }

    return GRAVITY_OK;
}

void batch_compress_auth (struct hash *node,
                          const struct batch_auth *auth,
                          const uint8_t *msg,
                          uint64_t len) {
    /* Compute Merkle tree root */
    int height = LOG_MAX_BATCH_COUNT;
    hash_to_N (node, msg, len);
    merkle_compress_auth (node, auth->index, auth->auth, height);
}
