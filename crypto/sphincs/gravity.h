/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#pragma once

#include "merkle.h"
#include "pors.h"

struct gravity_sk {
    struct hash seed;
    struct hash salt;
    struct hash cache[2 * GRAVITY_ccc - 1];
};

struct gravity_pk {
    struct hash k;
};

struct gravity_sign {
    struct hash rand;
    struct octoporst_sign op_sign;
    struct merkle_sign merkle[GRAVITY_d];
#if GRAVITY_c > 0
    struct hash auth[GRAVITY_c];
#endif
};

int gravity_gensk (struct gravity_sk *sk);

int gravity_genpk (const struct gravity_sk *sk, struct gravity_pk *pk);

int gravity_sign (const struct gravity_sk *sk, struct gravity_sign *sign, const struct hash *msg);

int gravity_verify (const struct gravity_pk *pk,
                    const struct gravity_sign *sign,
                    const struct hash *msg);

/* Serialization */
int gravity_loadsign (struct gravity_sign *sign, const uint8_t *_sign, size_t _len);

int gravity_signcmp (const struct gravity_sign *sign1, const struct gravity_sign *sign2);
