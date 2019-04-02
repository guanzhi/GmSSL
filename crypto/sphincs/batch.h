/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#pragma once

#include "hash.h"

struct batch_buf {
    struct hash buf[MAX_BATCH_COUNT];
    uint32_t count;
};

struct batch_group {
    struct hash tree[2 * MAX_BATCH_COUNT - 1];
    uint32_t count;
};

struct batch_auth {
    struct hash auth[LOG_MAX_BATCH_COUNT];
    uint32_t index;
};

int batch_init (struct batch_buf *buf);

int batch_append (struct batch_buf *buf, const uint8_t *msg, uint64_t len, uint32_t *index);

int batch_group (struct batch_group *group, struct batch_buf *buf);

int batch_extract (const struct batch_group *group, struct batch_auth *auth, uint32_t index);

void batch_compress_auth (struct hash *node,
                          const struct batch_auth *auth,
                          const uint8_t *msg,
                          uint64_t len);
