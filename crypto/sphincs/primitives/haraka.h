/*
The MIT License (MIT)

Copyright (c) 2016 Stefan Kölbl
original Haraka implementations

Copyright (c) 2017 Nagravision S.A.
changes by JP Aumasson, Guillaume Endignoux, 2017: improvements, non-ni versions

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */
#pragma once


#include <stdint.h>


static const uint32_t rc[48 * 4] = {
    0x75817b9d, 0xb2c5fef0, 0xe620c00a, 0x0684704c, 0x2f08f717, 0x640f6ba4,
    0x88f3a06b, 0x8b66b4e1, 0x9f029114, 0xcf029d60, 0x53f28498, 0x3402de2d,
    0xfd5b4f79, 0xbbf3bcaf, 0x2e7b4f08, 0x0ed6eae6, 0xbe397044, 0x79eecd1c,
    0x4872448b, 0xcbcfb0cb, 0x2b8a057b, 0x8d5335ed, 0x6e9032b7, 0x7eeacdee,
    0xda4fef1b, 0xe2412761, 0x5e2e7cd0, 0x67c28f43, 0x1fc70b3b, 0x675ffde2,
    0xafcacc07, 0x2924d9b0, 0xb9d465ee, 0xecdb8fca, 0xe6867fe9, 0xab4d63f1,
    0xad037e33, 0x5b2a404f, 0xd4b7cd64, 0x1c30bf84, 0x8df69800, 0x69028b2e,
    0x941723bf, 0xb2cc0bb9, 0x5c9d2d8a, 0x4aaa9ec8, 0xde6f5572, 0xfa0478a6,
    0x29129fd4, 0x0efa4f2e, 0x6b772a12, 0xdfb49f2b, 0xbb6a12ee, 0x32d611ae,
    0xf449a236, 0x1ea10344, 0x9ca8eca6, 0x5f9600c9, 0x4b050084, 0xaf044988,
    0x27e593ec, 0x78a2c7e3, 0x9d199c4f, 0x21025ed8, 0x82d40173, 0xb9282ecd,
    0xa759c9b7, 0xbf3aaaf8, 0x10307d6b, 0x37f2efd9, 0x6186b017, 0x6260700d,
    0xf6fc9ac6, 0x81c29153, 0x21300443, 0x5aca45c2, 0x36d1943a, 0x2caf92e8,
    0x226b68bb, 0x9223973c, 0xe51071b4, 0x6cbab958, 0x225886eb, 0xd3bf9238,
    0x24e1128d, 0x933dfddd, 0xaef0c677, 0xdb863ce5, 0xcb2212b1, 0x83e48de3,
    0xffeba09c, 0xbb606268, 0xc72bf77d, 0x2db91a4e, 0xe2e4d19c, 0x734bd3dc,
    0x2cb3924e, 0x4b1415c4, 0x61301b43, 0x43bb47c3, 0x16eb6899, 0x03b231dd,
    0xe707eff6, 0xdba775a8, 0x7eca472c, 0x8e5e2302, 0x3c755977, 0x6df3614b,
    0xb88617f9, 0x6d1be5b9, 0xd6de7d77, 0xcda75a17, 0xa946ee5d, 0x9d6c069d,
    0x6ba8e9aa, 0xec6b43f0, 0x3bf327c1, 0xa2531159, 0xf957332b, 0xcb1e6950,
    0x600ed0d9, 0xe4ed0353, 0x00da619c, 0x2cee0c75, 0x63a4a350, 0x80bbbabc,
    0x96e90cab, 0xf0b1a5a1, 0x938dca39, 0xab0dde30, 0x5e962988, 0xae3db102,
    0x2e75b442, 0x8814f3a8, 0xd554a40b, 0x17bb8f38, 0x360a16f6, 0xaeb6b779,
    0x5f427fd7, 0x34bb8a5b, 0xffbaafde, 0x43ce5918, 0xcbe55438, 0x26f65241,
    0x839ec978, 0xa2ca9cf7, 0xb9f3026a, 0x4ce99a54, 0x22901235, 0x40c06e28,
    0x1bdff7be, 0xae51a51a, 0x48a659cf, 0xc173bc0f, 0xba7ed22b, 0xa0c1613c,
    0xe9c59da1, 0x4ad6bdfd, 0x02288288, 0x756acc03, 0x848f2ad2, 0x367e4778,
    0x0de7d31e, 0x2ff37238, 0xb73bd58f, 0xee36b135, 0xcf74be8b, 0x08d95c6a,
    0xa3743e4a, 0x66ae1838, 0xc9d6ee98, 0x5880f434, 0x9a9369bd, 0xd0fdf4c7,
    0xaefabd99, 0x593023f0, 0x6f1ecb2a, 0xa5cc637b, 0xeb606e6f, 0x329ae3d1,
    0xcb7594ab, 0xa4dc93d6, 0x49e01594, 0xe00207eb, 0x65208ef8, 0x942366a6,
    0xf751c880, 0x1caa0c4f, 0xe3e67e4a, 0xbd03239f, 0xdb2dc1dd, 0x02f7f57f,
};

static const uint8_t sbox[256] =
{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
  0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
  0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7,
  0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
  0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
  0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
  0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe,
  0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
  0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
  0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
  0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
  0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2,
  0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
  0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
  0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86,
  0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
  0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
  0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

#define XT(x) (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b))

#define AES2(rci)                                                              \
    aesenc (s0, ((uint8_t *)rc) + 16 * (rci + 0));                             \
    aesenc (s1, ((uint8_t *)rc) + 16 * (rci + 1));                             \
    aesenc (s0, ((uint8_t *)rc) + 16 * (rci + 2));                             \
    aesenc (s1, ((uint8_t *)rc) + 16 * (rci + 3));

#define MIX2                                                                   \
    tmp[0] = ((uint32_t *)s0)[0];                                              \
    tmp[1] = ((uint32_t *)s1)[0];                                              \
    tmp[2] = ((uint32_t *)s0)[1];                                              \
    tmp[3] = ((uint32_t *)s1)[1];                                              \
    ((uint32_t *)s1)[0] = ((uint32_t *)s0)[2];                                 \
    ((uint32_t *)s1)[1] = ((uint32_t *)s1)[2];                                 \
    ((uint32_t *)s1)[2] = ((uint32_t *)s0)[3];                                 \
    ((uint32_t *)s0)[0] = tmp[0];                                              \
    ((uint32_t *)s0)[1] = tmp[1];                                              \
    ((uint32_t *)s0)[2] = tmp[2];                                              \
    ((uint32_t *)s0)[3] = tmp[3];

#define AES4(rci)                                                              \
    aesenc (s0, ((uint8_t *)rc) + 16 * (rci + 0));                             \
    aesenc (s1, ((uint8_t *)rc) + 16 * (rci + 1));                             \
    aesenc (s2, ((uint8_t *)rc) + 16 * (rci + 2));                             \
    aesenc (s3, ((uint8_t *)rc) + 16 * (rci + 3));                             \
    aesenc (s0, ((uint8_t *)rc) + 16 * (rci + 4));                             \
    aesenc (s1, ((uint8_t *)rc) + 16 * (rci + 5));                             \
    aesenc (s2, ((uint8_t *)rc) + 16 * (rci + 6));                             \
    aesenc (s3, ((uint8_t *)rc) + 16 * (rci + 7));

#define MIX4                                                                   \
    tmp[0] = ((uint32_t *)s0)[0];                                              \
    tmp[1] = ((uint32_t *)s1)[0];                                              \
    tmp[2] = ((uint32_t *)s0)[1];                                              \
    tmp[3] = ((uint32_t *)s1)[1];                                              \
    tmp[4] = ((uint32_t *)s3)[0];                                              \
    ((uint32_t *)s0)[0] = ((uint32_t *)s0)[2];                                 \
    ((uint32_t *)s0)[1] = ((uint32_t *)s1)[2];                                 \
    ((uint32_t *)s0)[2] = ((uint32_t *)s0)[3];                                 \
    ((uint32_t *)s0)[3] = ((uint32_t *)s1)[3];                                 \
    ((uint32_t *)s1)[0] = ((uint32_t *)s2)[0];                                 \
    ((uint32_t *)s1)[1] = ((uint32_t *)s3)[0];                                 \
    ((uint32_t *)s1)[2] = ((uint32_t *)s2)[1];                                 \
    ((uint32_t *)s1)[3] = ((uint32_t *)s3)[1];                                 \
    ((uint32_t *)s2)[0] = ((uint32_t *)s2)[2];                                 \
    ((uint32_t *)s2)[1] = ((uint32_t *)s3)[2];                                 \
    ((uint32_t *)s2)[2] = ((uint32_t *)s2)[3];                                 \
    ((uint32_t *)s2)[3] = ((uint32_t *)s3)[3];                                 \
    ((uint32_t *)s3)[0] = ((uint32_t *)s0)[0];                                 \
    ((uint32_t *)s3)[1] = ((uint32_t *)s2)[0];                                 \
    ((uint32_t *)s3)[2] = ((uint32_t *)s0)[1];                                 \
    ((uint32_t *)s3)[3] = ((uint32_t *)s2)[1];                                 \
    ((uint32_t *)s0)[0] = ((uint32_t *)s0)[2];                                 \
    ((uint32_t *)s0)[1] = ((uint32_t *)s2)[2];                                 \
    ((uint32_t *)s0)[2] = ((uint32_t *)s0)[3];                                 \
    ((uint32_t *)s0)[3] = ((uint32_t *)s2)[3];                                 \
    ((uint32_t *)s2)[0] = ((uint32_t *)s1)[2];                                 \
    ((uint32_t *)s2)[1] = tmp[2];                                              \
    ((uint32_t *)s2)[2] = ((uint32_t *)s1)[3];                                 \
    ((uint32_t *)s2)[3] = tmp[3];                                              \
    ((uint32_t *)s1)[0] = ((uint32_t *)s1)[0];                                 \
    ((uint32_t *)s1)[1] = tmp[0];                                              \
    ((uint32_t *)s1)[2] = tmp[4];                                              \
    ((uint32_t *)s1)[3] = tmp[1];


void haraka256_256(unsigned char *out, const unsigned char *in);
void haraka256_256_chain(unsigned char *out, const unsigned char *in, int chainlen);
void haraka512_256(unsigned char *out, const unsigned char *in);
