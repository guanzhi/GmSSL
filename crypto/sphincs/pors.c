/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#include "pors.h"

#include "aes.h"
#include "merkle.h"
#include <stdlib.h>

/* Naive PORS without Merkle tree */
void pors_gensk (const struct hash *key, const struct address *address, struct pors_sk *sk) {
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
    aesctr256 (sk->k->h, key->h, iv, PORS_t * HASH_SIZE);
}

void pors_sign (const struct pors_sk *sk, struct pors_sign *sign, const struct pors_subset *subset) {
    int i;
    int index;

    for (i = 0; i < PORS_k; ++i) {
        index = subset->s[i];
        hashcpy (&sign->s[i], &sk->k[index]);
    }
}


/* Naive PORST without merging of authentication paths */
int porst_genpk (const struct pors_sk *sk, struct porst_pk *pk) {
    struct hash *buf = merkle_alloc_buf (PORS_tau);
    if (buf == NULL) return GRAVITY_ERR_ALLOC;

    /* Leaves */
    hash_parallel (buf, sk->k, PORS_t);

    /* Merkle tree */
    merkle_compress_all (buf, PORS_tau, &pk->k);

    merkle_free_buf (buf);
    return GRAVITY_OK;
}


/* PORST with authentication octopus */
void sort_subset (struct pors_subset *subset) {
    /* Selection sort */
    int i, j, k, tmp;
    for (i = 0; i + 1 < PORS_k; ++i) {
        k = i;
        tmp = subset->s[k];
        for (j = i + 1; j < PORS_k; ++j) {
            if (subset->s[j] < tmp) {
                k = j;
                tmp = subset->s[k];
            }
        }

        subset->s[k] = subset->s[i];
        subset->s[i] = tmp;
    }
}

int octoporst_sign (const struct pors_sk *sk,
                    struct octoporst_sign *sign,
                    struct porst_pk *pk,
                    struct pors_subset *subset) {
    struct hash *buf;

    /* Sort subset */
    sort_subset (subset);

    /* Values */
    pors_sign (sk, &sign->s, subset);

    /* Authentication paths */
    buf = merkle_alloc_buf (PORS_tau);
    if (buf == NULL) return GRAVITY_ERR_ALLOC;

    /* Leaves */
    hash_parallel (buf, sk->k, PORS_t);

    /* Merkle tree */
    merkle_gen_octopus (buf, PORS_tau, sign->octopus, &sign->octolen, &pk->k,
                        subset->s, PORS_k);

    merkle_free_buf (buf);
    return GRAVITY_OK;
}

int octoporst_extract (struct porst_pk *pk,
                       const struct octoporst_sign *sign,
                       struct pors_subset *subset) {
    struct hash tmp[PORS_k];
    int res;

    /* Sort subset */
    sort_subset (subset);

    /* Compute leaves */
    hash_parallel (tmp, sign->s.s, PORS_k);

    /* Auth octopus */
    res = merkle_compress_octopus (tmp, PORS_tau, sign->octopus, sign->octolen,
                                   subset->s, PORS_k);
    if (res != GRAVITY_OK) return res;

    hashcpy (&pk->k, &tmp[0]);
    return GRAVITY_OK;
}


int octoporst_loadsign (struct octoporst_sign *sign, const uint8_t *_sign, size_t _len) {
    if (_len < sizeof (struct pors_sign)) return GRAVITY_ERR_VERIF;
    _len -= sizeof (struct pors_sign);

    if (_len % HASH_SIZE != 0) return GRAVITY_ERR_VERIF;
    _len /= HASH_SIZE;

    if (_len > PORS_k * PORS_tau) return GRAVITY_ERR_VERIF;

    memcpy (&sign->s, _sign, sizeof (struct pors_sign));
    _sign += sizeof (struct pors_sign);
    memcpy (sign->octopus, _sign, _len * HASH_SIZE);
    sign->octolen = _len;

    return GRAVITY_OK;
}

int octoporst_signcmp (const struct octoporst_sign *sign1,
                       const struct octoporst_sign *sign2) {
    if (sign1->octolen != sign2->octolen) return 1;
    if (hashcmpN (sign1->s.s, sign2->s.s, PORS_k)) return 1;
    if (hashcmpN (sign1->octopus, sign2->octopus, sign1->octolen)) return 1;

    return 0;
}


void pors_randsubset (const struct hash *rand,
                      const struct hash *msg,
                      uint64_t *address,
                      struct pors_subset *subset) {
#define BYTES_PER_INDEX 4
#define STREAMLEN                                                              \
    ((8 * (PORS_k)) + HASH_SIZE) /* count twice as many indexes as needed */
    uint8_t randstream[STREAMLEN];
    int index, duplicate, i, count = 0;
    size_t offset = 0;
    struct hash seed;
    struct hash buf[2];
    uint64_t addr;
    uint8_t byte;

    hashcpy (&buf[0], rand);
    hashcpy (&buf[1], msg);
    hash_2N_to_N (&seed, buf);

    aesctr256_zeroiv (randstream, seed.h, STREAMLEN);

    /* compute address */
    addr = 0;
    for (i = 0; i < HASH_SIZE; ++i) {
        byte = randstream[i];
        addr = (addr << 8) | byte;
        addr &= GRAVITY_mask;
    }
    *address = addr;

    while (count < PORS_k) {
        /* ok to take mod since T is a power of 2 */
        index = U8TO32 (randstream + HASH_SIZE + offset) % PORS_t;
        offset += BYTES_PER_INDEX;
        duplicate = 0;
        for (i = 0; i < count; ++i)
            if (subset->s[i] == index) duplicate++;
        if (!duplicate) {
            subset->s[count] = index;
            count++;
        }
    }
}
