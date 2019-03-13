/*
 * Copyright (C) 2017 Nagravision S.A.
 */

#include "gravity.h"
#include "randombytes.h"
#include "sign.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define SKLEN sizeof (struct gravity_sk)
#define PKLEN sizeof (struct gravity_pk)
#define SIGLEN sizeof (struct gravity_sign)
#define N 32
#define ROUNDS 3


int main () {

    unsigned long long smlen;
    unsigned long long mlen = N;
    uint8_t sk[SKLEN];
    uint8_t pk[PKLEN];
    uint8_t m[N];
    uint8_t *sm = malloc (N + SIGLEN);
    struct timeval tm1, tm2;
    unsigned long long usecs;
    int ret = -1;
    int i;

    if (!sm) {
        fprintf (stderr, "error: sm malloc failed\n");
        ret = 1;
        goto label_exit_0;
    }

    printf ("k\t%d\n", PORS_k);
    printf ("h\t%d\n", MERKLE_h);
    printf ("d\t%d\n", GRAVITY_d);
    printf ("c\t%d\n", GRAVITY_c);
    printf ("sk len\t%d\n", (int)SKLEN);
    printf ("pk len\t%d\n", (int)PKLEN);
    printf ("sig len\t%d\n", (int)SIGLEN);

#define MEASURE(s)                                                                 \
    do {                                                                           \
        gettimeofday (&tm2, NULL);                                                 \
        usecs = 1000000 * (tm2.tv_sec - tm1.tv_sec) + (tm2.tv_usec - tm1.tv_usec); \
        printf ("\n# %s\n", s);                                                    \
        printf ("%.2f usec\n", (double)usecs);                                     \
    } while (0)

    randombytes (m, N);

    gettimeofday (&tm1, NULL);

    if (crypto_sign_keypair (pk, sk)) {
        fprintf (stderr, "error: crypto_sign_keypair failed\n");
        ret = 1;
        goto label_exit_2;
    }

    MEASURE ("crypto_sign_keypair");

    for (i = 0; i < ROUNDS; ++i) {

        gettimeofday (&tm1, NULL);

        if (crypto_sign (sm, &smlen, m, mlen, sk)) {
            fprintf (stderr, "error: crypto_sign failed\n");
            ret = 1;
            goto label_exit_2;
        }

        MEASURE ("crypto_sign");
        gettimeofday (&tm1, NULL);


        if (crypto_sign_open (m, &mlen, sm, smlen, pk)) {
            fprintf (stderr, "error: crypto_sign_open failed\n");
            ret = 1;
            goto label_exit_2;
        }

        m[0] ^= sm[33];

        MEASURE ("crypto_sign_open");
    }

    ret = 0;
label_exit_2:
    free (sm);
label_exit_0:
    return ret;
}
