/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#pragma once

#include "hash.h"

/* PRNG to obtain a random subset */
struct pors_subset {
    int s[PORS_k];
};

void pors_randsubset (const struct hash *rand,
                      const struct hash *msg,
                      uint64_t *address,
                      struct pors_subset *subset);


/* Naive PORS without Merkle tree */
struct pors_sk {
    struct hash k[PORS_t];
};

struct pors_pk {
    struct hash k[PORS_t];
};

struct pors_keypair {
    struct pors_sk sk;
    struct pors_pk pk;
};

struct pors_sign {
    struct hash s[PORS_k];
};

void pors_gensk (const struct hash *key, const struct address *address, struct pors_sk *sk);

void pors_sign (const struct pors_sk *sk, struct pors_sign *sign, const struct pors_subset *subset);


/* Naive PORST without merging of authentication paths */
struct porst_pk {
    struct hash k;
};

struct porst_keypair {
    struct pors_sk sk;
    struct porst_pk pk;
};

int porst_genpk (const struct pors_sk *sk, struct porst_pk *pk);


/* PORST with authentication octopus */
struct octoporst_sign {
    struct pors_sign s;
    struct hash octopus[PORS_k * PORS_tau]; /* Large enough buffer */
    int octolen; /* Number of elements in the octopus */
};

int octoporst_sign (const struct pors_sk *sk,
                    struct octoporst_sign *sign,
                    struct porst_pk *pk,
                    struct pors_subset *subset);

int octoporst_extract (struct porst_pk *pk,
                       const struct octoporst_sign *sign,
                       struct pors_subset *subset);

/* Serialization */
int octoporst_loadsign (struct octoporst_sign *sign, const uint8_t *_sign, size_t _len);

int octoporst_signcmp (const struct octoporst_sign *sign1, const struct octoporst_sign *sign2);
