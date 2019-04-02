/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#pragma once

#include "common.h"

#include <stdint.h>
#include <string.h>

/* TODO: portable alignment */
struct hash {
    uint8_t h[HASH_SIZE];
} __attribute__ ((aligned (16)));

struct address {
    uint64_t index;
    uint32_t layer;
};


void hash_N_to_N (struct hash *dst, const struct hash *src);
void hash_N_to_N_chain (struct hash *dst, const struct hash *src, int chainlen);
void hash_2N_to_N (struct hash *dst, const struct hash *src);
void hash_to_N (struct hash *dst, const uint8_t *src, uint64_t srclen);

/* Compress 2*count input hashes into count output hashes, pairwise */
void hash_compress_pairs (struct hash *dst, const struct hash *src, int count);
/* Compress count hashes into a single hash */
void hash_compress_all (struct hash *dst, const struct hash *src, int count);
/* Compute count hashes in parallel */
void hash_parallel (struct hash *dst, const struct hash *src, int count);
/* Compute count hash chains of length chainlen in parallel */
void hash_parallel_chains (struct hash *dst, const struct hash *src, int count, int chainlen);


/* int hashcmp(const struct hash *a, const struct hash *b); */
#define hashcmp(a, b) memcmp ((a)->h, (b)->h, HASH_SIZE)
/* int hashcmpN(const struct hash *a, const struct hash *b, size_t count); */
#define hashcmpN(a, b, N) memcmp ((a)->h, (b)->h, (N)*HASH_SIZE)
/* void hashcpy(struct hash *dst, const struct hash *src); */
#define hashcpy(a, b) memcpy ((a)->h, (b)->h, HASH_SIZE)
/* void hashcpyN(struct hash *dst, const struct hash *src, size_t count); */
#define hashcpyN(a, b, N) memcpy ((a)->h, (b)->h, (N)*HASH_SIZE)
/* void hashzero(struct hash *dst); */
#define hashzero(a) memset ((a)->h, 0, HASH_SIZE)
/* void swap(struct hash *a, struct hash *b, struct hash *tmp); */
#define hashswap(a, b, tmp)                                                    \
    do {                                                                       \
        (tmp) = (a);                                                           \
        (a) = (b);                                                             \
        (b) = (tmp);                                                           \
    } while (0);
