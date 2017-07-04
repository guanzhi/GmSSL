/*====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */


// Simon Tests 


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <openssl/simon.h>

int main(int argc, char** argv){
    // Create reuseable cipher objects for each alogirthm type
    simon_cipher my_simon_cipher = *(simon_cipher *)malloc(sizeof(simon_cipher));

    // Create generic tmp variables
    uint8_t ciphertext_buffer[16];
    uint32_t result;

    // Initialize IV and Counter Values for Use with Block Modes
    uint8_t my_IV[] = {0x32,0x14,0x76,0x58};
    uint8_t my_counter[] = {0x2F,0x3D,0x5C,0x7B};
    int i, error_sum;
    error_sum = 0;


    // Simon 64/32 Test
    // Key: 1918 1110 0908 0100 Plaintext: 6565 6877 Ciphertext: c69b e9bb
    uint8_t simon64_32_key[] = {0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19};
    uint8_t simon64_32_plain[] = {0x77, 0x68, 0x65, 0x65};
    uint8_t simon64_32_cipher[] = {0xBB,0xE9, 0x9B, 0xC6};
    result = simon_init(&my_simon_cipher, simon_64_32, ECB, simon64_32_key, my_IV, my_counter);
    simon_encrypt(my_simon_cipher, &simon64_32_plain, &ciphertext_buffer);
    for(i = 0; i < 4; i++) {
        if (ciphertext_buffer[i] != simon64_32_cipher[i])
            error_sum++;
    } 
    simon_decrypt(my_simon_cipher, &simon64_32_cipher, &ciphertext_buffer);
    for(i = 0; i < 4; i++) {
        if (ciphertext_buffer[i] != simon64_32_plain[i]) 
            error_sum++;
    }


    // Simon 72/48 Test
    // Key: 121110 0a0908 020100 Plaintext: 612067 6e696c Ciphertext: dae5ac 292cac
    uint8_t simon72_48_key[] = {0x00, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x10, 0x11, 0x12};
    uint8_t simon72_48_plain[] = {0x6c, 0x69, 0x6E, 0x67, 0x20, 0x61};
    uint8_t simon72_48_cipher[] = {0xAC, 0x2C, 0x29, 0xAC, 0xE5, 0xda};
    result = simon_init(&my_simon_cipher, simon_72_48, ECB, simon72_48_key, my_IV, my_counter);
    simon_encrypt(my_simon_cipher, &simon72_48_plain, &ciphertext_buffer);
    for(i = 0; i < 6; i++) {
        if (ciphertext_buffer[i] != simon72_48_cipher[i]) 
           error_sum++;
    }
    simon_decrypt(my_simon_cipher, &simon72_48_cipher, &ciphertext_buffer);
    for(i = 0; i < 6; i++) {
        if (ciphertext_buffer[i] != simon72_48_plain[i]) 
            error_sum++;
    }


    // Simon 96/48 Test
    // Key: 1a1918 121110 0a0908 020100 Plaintext: 726963 20646e Ciphertext: 6e06a5 acf156
    uint8_t simon96_48_key[] = {0x00, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x10, 0x11, 0x12, 0x18, 0x19, 0x1a};
    uint8_t simon96_48_plain[] = {0x6e, 0x64, 0x20, 0x63, 0x69, 0x72};
    uint8_t simon96_48_cipher[] = {0x56, 0xf1, 0xac, 0xa5, 0x06, 0x6e};
    result = simon_init(&my_simon_cipher, simon_96_48, ECB, simon96_48_key, my_IV, my_counter);
    simon_encrypt(my_simon_cipher, &simon96_48_plain, &ciphertext_buffer);
    for(i = 0; i < 6; i++) {
        if (ciphertext_buffer[i] != simon96_48_cipher[i]) 
            error_sum++;
    }
    simon_decrypt(my_simon_cipher, &simon96_48_cipher, &ciphertext_buffer);
    for(i = 0; i < 6; i++) {
        if (ciphertext_buffer[i] != simon96_48_plain[i]) 
            error_sum++;
    }


    // Simon 96/64 Test
    // Key: 13121110 0b0a0908 03020100 Plaintext: 6f722067 6e696c63 Ciphertext: 5ca2e27f 111a8fc8
    uint8_t simon96_64_key[] = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13};
    uint8_t simon96_64_plain[] = {0x63, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x72, 0x6f};
    uint8_t simon96_64_cipher[] = {0xc8, 0x8f, 0x1a, 0x11, 0x7f, 0xe2, 0xa2, 0x5c};
    result = simon_init(&my_simon_cipher, simon_96_64, ECB, simon96_64_key, my_IV, my_counter);
    simon_encrypt(my_simon_cipher, &simon96_64_plain, &ciphertext_buffer);
    for(i = 0; i < 8; i++) {
        if (ciphertext_buffer[i] != simon96_64_cipher[i]) 
            error_sum++;
    }
    simon_decrypt(my_simon_cipher, &simon96_64_cipher, &ciphertext_buffer);
    for(i = 0; i < 8; i++) {
        if (ciphertext_buffer[i] != simon96_64_plain[i]) 
            error_sum++;
    }


    // Simon 128/64 Test
    // Key: 1b1a1918 13121110 0b0a0908 03020100 Plaintext: 656b696c 20646e75 Ciphertext: 44c8fc20 b9dfa07a
    uint8_t simon128_64_key[] = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B};
    uint8_t simon128_64_plain[] = {0x75, 0x6e, 0x64, 0x20, 0x6c, 0x69, 0x6b, 0x65};
    uint8_t simon128_64_cipher[] = {0x7a, 0xa0, 0xdf, 0xb9, 0x20, 0xfc, 0xc8, 0x44};
    result = simon_init(&my_simon_cipher, simon_128_64, ECB, simon128_64_key, my_IV, my_counter);
    simon_encrypt(my_simon_cipher, &simon128_64_plain, &ciphertext_buffer);
    for(i = 0; i < 8; i++) {
        if (ciphertext_buffer[i] != simon128_64_cipher[i]) 
            error_sum++;
    }
    simon_decrypt(my_simon_cipher, &simon128_64_cipher, &ciphertext_buffer);
    for(i = 0; i < 8; i++) {
        if (ciphertext_buffer[i] != simon128_64_plain[i]) 
            error_sum++;
    }


    // Simon 96/96 Test
    // Key: 0d0c0b0a0908 050403020100 Plaintext: 2072616c6c69 702065687420 Ciphertext: 602807a462b4 69063d8ff082
    uint8_t simon96_96_key[] = {0x00, 0x01, 0x02, 0x03,0x04,0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D};
    uint8_t simon96_96_plain[] = {0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x69, 0x6c, 0x6c, 0x61, 0x72, 0x20};
    uint8_t simon96_96_cipher[] = {0x82, 0xf0, 0x8f, 0x3d, 0x06, 0x69, 0xb4, 0x62, 0xa4, 0x07, 0x28, 0x60};
    result = simon_init(&my_simon_cipher, simon_96_96, ECB, simon96_96_key, my_IV, my_counter);
    simon_encrypt(my_simon_cipher, &simon96_96_plain, &ciphertext_buffer);
    for(i = 0; i < 12; i++) {
        if (ciphertext_buffer[i] != simon96_96_cipher[i]) 
            error_sum++;
    }
    simon_decrypt(my_simon_cipher, &simon96_96_cipher, &ciphertext_buffer);
    for(i = 0; i < 12; i++) {
        if (ciphertext_buffer[i] != simon96_96_plain[i])
            error_sum++;
    }


    // Simon 144/96 Test
    // Key: 151413121110 0d0c0b0a0908 050403020100 Plaintext: 746168742074 73756420666f Ciphertext: ecad1c6c451e 3f59c5db1ae9
    uint8_t simon144_96_key[] = {0x00, 0x01, 0x02, 0x03,0x04,0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    uint8_t simon144_96_plain[] = {0x6f, 0x66, 0x20, 0x64, 0x75, 0x73, 0x74, 0x20, 0x74, 0x68, 0x61, 0x74};
    uint8_t simon144_96_cipher[] = {0xe9, 0x1a, 0xdb, 0xc5, 0x59, 0x3f, 0x1e, 0x45, 0x6c, 0x1c, 0xad, 0xec};
    result = simon_init(&my_simon_cipher, simon_144_96, ECB, simon144_96_key, my_IV, my_counter);
    simon_encrypt(my_simon_cipher, &simon144_96_plain, &ciphertext_buffer);
    for(i = 0; i < 12; i++) {
        if (ciphertext_buffer[i] != simon144_96_cipher[i]) 
            error_sum++;
    }
    simon_decrypt(my_simon_cipher, &simon144_96_cipher, &ciphertext_buffer);
    for(i = 0; i < 12; i++) {
        if (ciphertext_buffer[i] != simon144_96_plain[i]) 
            error_sum++;
    }


    // Simon 128/128 Test
    // Key: 0f0e0d0c0b0a0908 0706050403020100 Plaintext: 6373656420737265 6c6c657661727420 Ciphertext: 49681b1e1e54fe3f 65aa832af84e0bbc
    uint8_t simon128_128_key[] = {0x00, 0x01, 0x02, 0x03,0x04, 0x05, 0x06,0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t simon128_128_plain[] = {0x20, 0x74, 0x72, 0x61, 0x76, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x73, 0x20, 0x64, 0x65, 0x73, 0x63};
    uint8_t simon128_128_cipher[] = {0xbc, 0x0b, 0x4e, 0xf8, 0x2a, 0x83, 0xaa, 0x65, 0x3f, 0xfe, 0x54, 0x1e, 0x1e, 0x1b, 0x68, 0x49};
    result = simon_init(&my_simon_cipher, simon_128_128, ECB, simon128_128_key, my_IV, my_counter);
    simon_encrypt(my_simon_cipher, &simon128_128_plain, &ciphertext_buffer);
    for(i = 0; i < 16; i++) {
        if (ciphertext_buffer[i] != simon128_128_cipher[i]) 
            error_sum++;
    }
    simon_decrypt(my_simon_cipher, &simon128_128_cipher, &ciphertext_buffer);
    for(i = 0; i < 16; i++) {
        if (ciphertext_buffer[i] != simon128_128_plain[i]) 
            error_sum++;
    }


    // Simon 192/128 Test
    // Key: 1716151413121110 0f0e0d0c0b0a0908 0706050403020100 Plaintext: 206572656874206e 6568772065626972 Ciphertext: c4ac61effcdc0d4f 6c9c8d6e2597b85b
    uint8_t simon192_128_key[] = {0x00, 0x01, 0x02, 0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    uint8_t simon192_128_plain[] = {0x72, 0x69, 0x62, 0x65, 0x20, 0x77, 0x68, 0x65, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x20};
    uint8_t simon192_128_cipher[] = {0x5b, 0xb8, 0x97, 0x25, 0x6e, 0x8d, 0x9c, 0x6c, 0x4f, 0x0d, 0xdc, 0xfc, 0xef, 0x61, 0xac, 0xc4};
    result = simon_init(&my_simon_cipher, simon_192_128, ECB, simon192_128_key, my_IV, my_counter);
    simon_encrypt(my_simon_cipher, &simon192_128_plain, &ciphertext_buffer);
    for(i = 0; i < 16; i++) {
        if (ciphertext_buffer[i] != simon192_128_cipher[i]) 
            error_sum++;
    }
    simon_decrypt(my_simon_cipher, &simon192_128_cipher, &ciphertext_buffer);
    for(i = 0; i < 16; i++) {
        if (ciphertext_buffer[i] != simon192_128_plain[i]) 
            error_sum++;
    }


    // Simon 256/128 Test
    // Key: 1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100 Plaintext: 74206e69206d6f6f 6d69732061207369 Ciphertext: 8d2b5579afc8a3a0 3bf72a87efe7b868
    uint8_t simon256_128_key[] = {0x00, 0x01, 0x02, 0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1d, 0x1e, 0x1f};
    uint8_t simon256_128_plain[] = {0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6d, 0x6f, 0x6f, 0x6d, 0x20, 0x69, 0x6e, 0x20, 0x74};
    uint8_t simon256_128_cipher[] = {0x68, 0xb8, 0xe7, 0xef, 0x87, 0x2a, 0xf7, 0x3b, 0xa0, 0xa3, 0xc8, 0xaf, 0x79, 0x55, 0x2b, 0x8d};
    result = simon_init(&my_simon_cipher, simon_256_128, ECB, simon256_128_key, my_IV, my_counter);
    simon_encrypt(my_simon_cipher, &simon256_128_plain, &ciphertext_buffer);
    for(i = 0; i < 16; i++) {
        if (ciphertext_buffer[i] != simon256_128_cipher[i]) 
            error_sum++;
    }
    simon_decrypt(my_simon_cipher, &simon256_128_cipher, &ciphertext_buffer);
    for(i = 0; i < 16; i++) {
        if (ciphertext_buffer[i] != simon256_128_plain[i]) 
            error_sum++;
    }
    return error_sum;
}
