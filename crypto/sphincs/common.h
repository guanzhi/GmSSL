/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#pragma once

#define HASH_SIZE 32

#define WOTS_LOG_ell1 6
#define WOTS_ell1 (1 << (WOTS_LOG_ell1))
#define WOTS_chksum 3
#define WOTS_ell ((WOTS_ell1) + (WOTS_chksum))
#define WOTS_w 16

/* set by compile flags */
#if 0
#define PORS_k 28
#define MERKLE_h 5
#define GRAVITY_d 10
#define GRAVITY_c 14
#endif

#define PORS_tau 16
#define PORS_t (1 << (PORS_tau))

#define MERKLE_hhh (1 << (MERKLE_h))

#define GRAVITY_ccc (1 << (GRAVITY_c))
#define GRAVITY_h ((MERKLE_h) * (GRAVITY_d) + (GRAVITY_c))

#if GRAVITY_h < 64
#define GRAVITY_mask ~(0xFFFFFFFFFFFFFFFFull << (GRAVITY_h))
#else
#define GRAVITY_mask 0xFFFFFFFFFFFFFFFFull
#endif

#define LOG_MAX_BATCH_COUNT 10
#define MAX_BATCH_COUNT (1 << (LOG_MAX_BATCH_COUNT))


#define GRAVITY_OK 0
#define GRAVITY_ERR_VERIF 1
#define GRAVITY_ERR_ALLOC 2
#define GRAVITY_ERR_BATCH 3

#define U8TO32(p)                                                              \
    (((uint32_t) ((p)[0]) << 24) | ((uint32_t) ((p)[1]) << 16) |               \
     ((uint32_t) ((p)[2]) << 8) | ((uint32_t) ((p)[3])))
