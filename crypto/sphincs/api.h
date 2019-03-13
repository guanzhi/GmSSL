#pragma once

#ifndef CRYPTO_BYTES

/* setting CRYPTO_BYTES to the static structure size, for simplicity,
   as opposed to the actual message-dependent signature size */

#define CRYPTO_ALGNAME "Gravity-SPHINCS S"
#define CRYPTO_SECRETKEYBYTES 65568
#define CRYPTO_PUBLICKEYBYTES 32
#define CRYPTO_BYTES 15728 // 12640

#if 0
#define CRYPTO_ALGNAME "Gravity-SPHINCS M"
#define CRYPTO_SECRETKEYBYTES 2097184
#define CRYPTO_PUBLICKEYBYTES 32
#define CRYPTO_BYTES 34064 // 28929
#endif

#if 0
#define CRYPTO_ALGNAME "Gravity-SPHINCS L"
#define CRYPTO_SECRETKEYBYTES 1048608
#define CRYPTO_PUBLICKEYBYTES 32
#define CRYPTO_BYTES 38768 // 35168
#endif

#endif

int crypto_sign_keypair (unsigned char *pk, unsigned char *sk);

int crypto_sign (unsigned char *sm,
                 unsigned long long *smlen,
                 const unsigned char *m,
                 unsigned long long mlen,
                 const unsigned char *sk);

int crypto_sign_open (unsigned char *m,
                      unsigned long long *mlen,
                      const unsigned char *sm,
                      unsigned long long smlen,
                      const unsigned char *pk);
