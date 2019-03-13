/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#pragma once

#include "common.h"
#include "hash.h"

/* Naive WOTS without L-tree nor masks */
struct wots_sk {
    struct hash k[WOTS_ell];
};

struct wots_pk {
    struct hash k[WOTS_ell];
};

struct wots_sign {
    struct hash s[WOTS_ell];
};

void wots_gensk (const struct hash *key, const struct address *address, struct wots_sk *sk);

void wots_sign (const struct wots_sk *sk, struct wots_sign *sign, const struct hash *msg);


/* WOTS with L-tree and without masks */
struct lwots_pk {
    struct hash k;
};

void lwots_genpk (const struct wots_sk *sk, struct lwots_pk *pk);

void lwots_extract (struct lwots_pk *pk, const struct wots_sign *sign, const struct hash *msg);
