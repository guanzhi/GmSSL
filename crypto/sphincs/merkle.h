/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#pragma once

#include "wots.h"

struct merkle_pk {
    struct hash k;
};

struct merkle_sign {
    struct wots_sign wots;
    struct hash auth[MERKLE_h];
};

int merkle_genpk (const struct hash *key, const struct address *address, struct merkle_pk *pk);

int merkle_sign (const struct hash *key,
                 const struct address *address,
                 struct merkle_sign *sign,
                 const struct hash *msg,
                 struct merkle_pk *pk);

void merkle_extract (struct merkle_pk *pk,
                     const struct address *address,
                     const struct merkle_sign *sign,
                     const struct hash *msg);


/* Helper functions */
/* Alloc/free a buffer large enough to store leaves and compress them */
struct hash *merkle_alloc_buf (int height);

void merkle_free_buf (struct hash *buf);

/* Compress leaves from level height to root */
void merkle_compress_all (struct hash *buf, int height, struct hash *root);

/* Compute authentication path */
void merkle_gen_auth (struct hash *buf, int height, struct hash *auth, int index, struct hash *root);

/* Compress node with its auth path on height_diff levels */
int merkle_compress_auth (struct hash *node, int index, const struct hash *auth, int height_diff);

/* "indices" must be sorted */
void merkle_gen_octopus (struct hash *buf,
                         int height,
                         struct hash *octopus,
                         int *octolen,
                         struct hash *root,
                         int *indices,
                         int count);

/* Compress a set of leaves with their auth path */
/* "indices" must be sorted */
int merkle_compress_octopus (struct hash *nodes,
                             int height,
                             const struct hash *octopus,
                             int octolen,
                             int *indices,
                             int count);
