// sm4ni.c
// 2018-04-20  Markku-Juhani O. Saarinen <mjos@iki.fi>

// Vectorized implementation of SM4. Uses affine transformations and AES NI
// to implement the SM4 S-Box.

//#include "sm4_ref.h"
#include <x86intrin.h>

// Encrypt 4 blocks (64 bytes) in ECB mode

void sm4_encrypt4(const uint32_t rk[32], void *src, const void *dst)
{
    // nibble mask
    const __m128i c0f __attribute__((aligned(0x10))) =
        { 0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F };

    // flip all bytes in all 32-bit words
    const __m128i flp __attribute__((aligned(0x10))) =
        { 0x0405060700010203, 0x0C0D0E0F08090A0B };

    // inverse shift rows
    const __m128i shr __attribute__((aligned(0x10))) =
        { 0x0B0E0104070A0D00, 0x0306090C0F020508 };

    // Affine transform 1 (low and high hibbles)
    const __m128i m1l __attribute__((aligned(0x10))) =
        { 0x9197E2E474720701, 0xC7C1B4B222245157 };
    const __m128i m1h __attribute__((aligned(0x10))) =
        { 0xE240AB09EB49A200, 0xF052B91BF95BB012 };

    // Affine transform 2 (low and high hibbles)
    const __m128i m2l __attribute__((aligned(0x10))) =
        { 0x5B67F2CEA19D0834, 0xEDD14478172BBE82 };
    const __m128i m2h __attribute__((aligned(0x10))) =
        { 0xAE7201DD73AFDC00, 0x11CDBE62CC1063BF };

    // left rotations of 32-bit words by 8-bit increments
    const __m128i r08 __attribute__((aligned(0x10))) =
        { 0x0605040702010003, 0x0E0D0C0F0A09080B };
    const __m128i r16 __attribute__((aligned(0x10))) =
        { 0x0504070601000302, 0x0D0C0F0E09080B0A };
    const __m128i r24 __attribute__((aligned(0x10))) =
        { 0x0407060500030201, 0x0C0F0E0D080B0A09 };

    __m128i x, y, t0, t1, t2, t3;

    uint32_t k, *p32, v[4] __attribute__((aligned(0x10)));
    int i;

    p32 = (uint32_t *) src;
    t0 = _mm_set_epi32(p32[12], p32[ 8], p32[ 4], p32[ 0]);
    t0 = _mm_shuffle_epi8(t0, flp);
    t1 = _mm_set_epi32(p32[13], p32[ 9], p32[ 5], p32[ 1]);
    t1 = _mm_shuffle_epi8(t1, flp);
    t2 = _mm_set_epi32(p32[14], p32[10], p32[ 6], p32[ 2]);
    t2 = _mm_shuffle_epi8(t2, flp);
    t3 = _mm_set_epi32(p32[15], p32[11], p32[ 7], p32[ 3]);
    t3 = _mm_shuffle_epi8(t3, flp);

    for (i = 0; i < 32; i++) {

        k = rk[i];
        x = t1 ^ t2 ^ t3 ^ _mm_set_epi32(k, k, k, k);

        y = _mm_and_si128(x, c0f);          // inner affine
        y = _mm_shuffle_epi8(m1l, y);
        x = _mm_srli_epi64(x, 4);
        x = _mm_and_si128(x, c0f);
        x = _mm_shuffle_epi8(m1h, x) ^ y;

        x = _mm_shuffle_epi8(x, shr);       // inverse MixColumns
        x = _mm_aesenclast_si128(x, c0f);   // AESNI instruction

        y = _mm_andnot_si128(x, c0f);       // outer affine
        y = _mm_shuffle_epi8(m2l, y);
        x = _mm_srli_epi64(x, 4);
        x = _mm_and_si128(x, c0f);
        x = _mm_shuffle_epi8(m2h, x) ^ y;

        // 4 parallel L1 linear transforms
        y = x ^ _mm_shuffle_epi8(x, r08) ^ _mm_shuffle_epi8(x, r16);
        y = _mm_slli_epi32(y, 2) ^ _mm_srli_epi32(y, 30);
        x = x ^ y ^ _mm_shuffle_epi8(x, r24);

        // rotate registers
        x ^= t0;
        t0 = t1;
        t1 = t2;
        t2 = t3;
        t3 = x;
    }

    p32 = (uint32_t *) dst;

    _mm_store_si128((__m128i *) v, _mm_shuffle_epi8(t3, flp));
    p32[ 0] = v[0];
    p32[ 4] = v[1];
    p32[ 8] = v[2];
    p32[12] = v[3];

    _mm_store_si128((__m128i *) v, _mm_shuffle_epi8(t2, flp));
    p32[ 1] = v[0];
    p32[ 5] = v[1];
    p32[ 9] = v[2];
    p32[13] = v[3];

    _mm_store_si128((__m128i *) v, _mm_shuffle_epi8(t1, flp));
    p32[ 2] = v[0];
    p32[ 6] = v[1];
    p32[10] = v[2];
    p32[14] = v[3];

    _mm_store_si128((__m128i *) v, _mm_shuffle_epi8(t0, flp));
    p32[ 3] = v[0];
    p32[ 7] = v[1];
    p32[11] = v[2];
    p32[15] = v[3];
}

