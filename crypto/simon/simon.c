/* ====================================================================
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


#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/simon.h>

// Cipher Operation Macros
#define shift_one ((x_word << 1) | (x_word >> (word_size - 1)))
#define shift_eight ((x_word << 8) | (x_word >> (word_size - 8)))
#define shift_two ((x_word << 2) | (x_word >> (word_size - 2)))
#define rshift_three(x) (x >> 3) |((x & 0x7) << (word_size - 3))
#define rshift_one(x)   (x >> 1) |((x & 0x1) << (word_size - 1))

uint64_t z_arrays[5] = {0b0001100111000011010100100010111110110011100001101010010001011111,
                        0b0001011010000110010011111011100010101101000011001001111101110001,
                        0b0011001101101001111110001000010100011001001011000000111011110101,
                        0b0011110000101100111001010001001000000111101001100011010111011011,
                        0b0011110111001001010011000011101000000100011011010110011110001011};

// Valid Cipher Parameters
const uint8_t simon_rounds[] = {32, 36, 36, 42, 44, 52, 54, 68, 69, 72};
const uint8_t simon_block_sizes[] = {32, 48, 48, 64, 64, 96, 96, 128, 128, 128};
const uint16_t simon_key_sizes[] = {64, 72, 96, 96, 128, 96, 144, 128, 192, 256};
const uint8_t  z_assign[] = {0, 0, 1, 2, 3, 2, 3, 2, 3, 4};

uint8_t simon_init(simon_cipher *cipher_object, enum simon_cipher_config_t cipher_cfg, enum mode_t c_mode, void *key, uint8_t *iv, uint8_t *counter) {

    if (cipher_cfg > Simon_256_128 || cipher_cfg < Simon_64_32){
        return -1;
    }
    
    cipher_object->block_size = simon_block_sizes[cipher_cfg];
    cipher_object->key_size = simon_key_sizes[cipher_cfg];
    cipher_object->round_limit = simon_rounds[cipher_cfg];
    cipher_object->cipher_cfg = cipher_cfg;
    cipher_object->z_seq = z_assign[cipher_cfg];
    uint8_t word_size = simon_block_sizes[cipher_cfg] >> 1;
    uint8_t word_bytes = word_size >> 3;
    uint8_t key_words =  simon_key_sizes[cipher_cfg] / word_size;
    uint64_t sub_keys[4] = {};
    uint64_t mod_mask = ULLONG_MAX >> (64 - word_size);

    
    // Setup
    int i, j;    
    for(i = 0; i < key_words; i++) {
        memcpy(&sub_keys[i], key + (word_bytes * i), word_bytes);
    }
    
    uint64_t tmp1,tmp2;
    uint64_t c = 0xFFFFFFFFFFFFFFFC; 
    
    // Store First Key Schedule Entry
    memcpy(cipher_object->key_schedule, &sub_keys[0], word_bytes);

    for(i = 0; i < simon_rounds[cipher_cfg] - 1; i++){
        tmp1 = rshift_three(sub_keys[key_words - 1]);
        
        if(key_words == 4) {
            tmp1 ^= sub_keys[1];
        }

        tmp2  = rshift_one(tmp1);
        tmp1 ^= sub_keys[0];
        tmp1 ^= tmp2;

        tmp2 = c ^ ((z_arrays[cipher_object->z_seq] >> (i % 62)) & 1);

        tmp1 ^= tmp2;

        // Shift Sub Words
        for(j = 0; j < (key_words - 1); j++){
            sub_keys[j] = sub_keys[j+1];
        }
        sub_keys[key_words - 1] = tmp1 & mod_mask;

        // Append sub key to key schedule
        memcpy(cipher_object->key_schedule + (word_bytes * (i+1)), &sub_keys[0], word_bytes);   
    }

    return 0;
}


uint8_t simon_encrypt(simon_cipher cipher_object, void *plaintext, void *ciphertext) {

    if (cipher_object.cipher_cfg == simon_64_32) {
        simon_encrypt32(cipher_object.key_schedule, plaintext, ciphertext);
    }
    
    else if(cipher_object.cipher_cfg <= simon_96_48) {
        simon_encrypt48(cipher_object.round_limit, cipher_object.key_schedule, plaintext, ciphertext);
    }
    
    else if(cipher_object.cipher_cfg <= simon_128_64) {
        simon_encrypt64(cipher_object.round_limit, cipher_object.key_schedule, plaintext, ciphertext);
    }
    
    else if(cipher_object.cipher_cfg <= simon_144_96) {
        simon_encrypt96(cipher_object.round_limit, cipher_object.key_schedule, plaintext, ciphertext);
    }

    else if(cipher_object.cipher_cfg <= simon_256_128) {
        simon_encrypt128(cipher_object.round_limit, cipher_object.key_schedule, plaintext, ciphertext);
    }
    
    else return -1;

    return 0;
}

void simon_encrypt32(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext) {
    
    const uint8_t word_size = 16;
    uint16_t y_word = *(uint16_t *)plaintext;
    uint16_t x_word = *(((uint16_t *)plaintext) + 1);
    uint16_t *round_key_ptr = (uint16_t *)key_schedule;
    uint16_t * word_ptr = (uint16_t *)ciphertext;


    uint8_t i;

    for(i = 0; i < 32; i++) {  // Block size 32 has only one round number option

        // Shift, AND , XOR ops
        uint16_t temp = (shift_one & shift_eight) ^ y_word ^ shift_two;
        
        // Feistel Cross
        y_word = x_word;
        
        // XOR with Round Key
        x_word = temp ^ *(round_key_ptr + i);
    }
    // Assemble Ciphertext Output Array   
    *word_ptr = y_word;
    *(word_ptr + 1) = x_word;
}

void simon_encrypt48(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext) {
    
    const uint8_t word_size = 24;

    bword_24 intrd = *(bword_24 *)plaintext;
    uint32_t y_word = intrd.data;
    intrd = *((bword_24 *)(plaintext+3));
    uint32_t x_word = intrd.data;

    uint8_t i;
    for(i = 0; i < round_limit; i++) {  // Block size 32 has only one round number option

        // Shift, AND , XOR ops
        uint32_t temp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        // Feistel Cross
        y_word = x_word;
        
        // XOR with Round Key
        x_word = (temp ^ (*((bword_24 *)(key_schedule + (i*3)))).data) & 0xFFFFFF;
    }
    // Assemble Ciphertext Output Array
    intrd.data = y_word;
    bword_24 * intrd_ptr = (bword_24 *)ciphertext; 
    *intrd_ptr = intrd;
    
    intrd.data = x_word;
    intrd_ptr = (bword_24 *)(ciphertext + 3);
    *intrd_ptr = intrd;
}

void simon_encrypt64(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext) {
    
    const uint8_t word_size = 32;
    uint32_t y_word = *(uint32_t *)plaintext;
    uint32_t x_word = *(((uint32_t *)plaintext) + 1);
    uint32_t *round_key_ptr = (uint32_t *)key_schedule;
    uint32_t *word_ptr = (uint32_t *)ciphertext;

    uint8_t i;
    for(i = 0; i < round_limit; i++) {  // Block size 32 has only one round number option

        // Shift, AND , XOR ops
        uint32_t temp = (shift_one & shift_eight) ^ y_word ^ shift_two;
        
        // Feistel Cross
        y_word = x_word;
        
        // XOR with Round Key
        x_word = temp ^ *(round_key_ptr + i);
    }
    // Assemble Ciphertext Output Array   
    *word_ptr = y_word;
    *(word_ptr + 1) = x_word;
}

void simon_encrypt96(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext) {
    
    const uint8_t word_size = 48;

    bword_48 intrd = *(bword_48 *)plaintext;
    uint64_t y_word = intrd.data;
    intrd = *((bword_48 *)(plaintext+6));
    uint64_t x_word = intrd.data;

    uint8_t i;
    for(i = 0; i < round_limit; i++) {  

        // Shift, AND , XOR ops
        uint64_t temp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        // Feistel Cross
        y_word = x_word;
        
        // XOR with Round Key
        x_word = (temp ^ (*((bword_48 *)(key_schedule + (i*6)))).data) & 0xFFFFFFFFFFFF;
    }
    // Assemble Ciphertext Output Array
    intrd.data = y_word;
    bword_48 * intrd_ptr = (bword_48 *)ciphertext; 
    *intrd_ptr = intrd;
    
    intrd.data = x_word;
    intrd_ptr = (bword_48 *)(ciphertext + 6);
    *intrd_ptr = intrd;
    
}

void simon_encrypt128(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext) {

    const uint8_t word_size = 64;
    uint64_t y_word = *(uint64_t *)plaintext;
    uint64_t x_word = *(((uint64_t *)plaintext) + 1);
    uint64_t *round_key_ptr = (uint64_t *)key_schedule;
    uint64_t *word_ptr = (uint64_t *)ciphertext;

    uint8_t i;
    for(i = 0; i < round_limit; i++) {  // Block size 32 has only one round number option

        // Shift, AND , XOR ops
        uint64_t temp = (shift_one & shift_eight) ^ y_word ^ shift_two;
        
        // Feistel Cross
        y_word = x_word;
        
        // XOR with Round Key
        x_word = temp ^ *(round_key_ptr + i);
    }
    // Assemble Ciphertext Output Array   
    *word_ptr = y_word;
    *(word_ptr + 1) = x_word;
}

uint8_t simon_decrypt(simon_cipher cipher_object, void *ciphertext, void *plaintext) {

    if (cipher_object.cipher_cfg == simon_64_32) {
        simon_decrypt32(cipher_object.key_schedule, ciphertext, plaintext);
    }
    
    else if(cipher_object.cipher_cfg <= simon_96_48) {
        simon_decrypt48(cipher_object.round_limit, cipher_object.key_schedule, ciphertext, plaintext);
    }
    
    else if(cipher_object.cipher_cfg <= simon_128_64) {
        simon_decrypt64(cipher_object.round_limit, cipher_object.key_schedule, ciphertext, plaintext);
    }
    
    else if(cipher_object.cipher_cfg <= simon_144_96) {
        simon_decrypt96(cipher_object.round_limit, cipher_object.key_schedule, ciphertext, plaintext);
    }

    else if(cipher_object.cipher_cfg <= simon_256_128) {
        simon_decrypt128(cipher_object.round_limit, cipher_object.key_schedule, ciphertext, plaintext);
    }
    
    else return -1;

    return 0;
}

void simon_decrypt32(uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext) {
    
    const uint8_t word_size = 16;
    uint16_t x_word = *(uint16_t *)ciphertext;
    uint16_t y_word = *(((uint16_t *)ciphertext) + 1);
    uint16_t *round_key_ptr = (uint16_t *)key_schedule;
    uint16_t * word_ptr = (uint16_t *)plaintext;

    int8_t i;
    for(i = 31; i >= 0; i--) {  // Block size 32 has only one round number option

        // Shift, AND , XOR ops
        uint16_t temp = (shift_one & shift_eight) ^ y_word ^ shift_two;
        
        // Feistel Cross
        y_word = x_word;
        
        // XOR with Round Key
        x_word = temp ^ *(round_key_ptr + i);
    }
    // Assemble Plaintext Output Array   
    *word_ptr = x_word;
    *(word_ptr + 1) = y_word;
    return;
}

void simon_decrypt48(uint8_t round_limit, uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext){
    const uint8_t word_size = 24;

    bword_24 intrd = *(bword_24 *)ciphertext;
    uint32_t x_word = intrd.data;
    intrd = *((bword_24 *)(ciphertext+3));
    uint32_t y_word = intrd.data;

    int8_t i;
    for(i = round_limit -1 ; i >= 0; i--) { 

        // Shift, AND , XOR ops
        uint32_t temp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        // Feistel Cross
        y_word = x_word;
        
        // XOR with Round Key
        x_word = (temp ^ (*((bword_24 *)(key_schedule + (i*3)))).data) & 0xFFFFFF;
    }
    // Assemble plaintext Output Array
    intrd.data = x_word;
    bword_24 * intrd_ptr = (bword_24 *)plaintext; 
    *intrd_ptr = intrd;
    
    intrd.data = y_word;
    intrd_ptr = (bword_24 *)(plaintext + 3);
    *intrd_ptr = intrd;
    return;
}
void simon_decrypt64(uint8_t round_limit, uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext){
    const uint8_t word_size = 32;
    uint32_t x_word = *(uint32_t *)ciphertext;
    uint32_t y_word = *(((uint32_t *)ciphertext) + 1);
    uint32_t *round_key_ptr = (uint32_t *)key_schedule;
    uint32_t *word_ptr = (uint32_t *)plaintext;

    int8_t i;
    for(i = round_limit -1 ; i >= 0; i--) { 

        // Shift, AND , XOR ops
        uint32_t temp = (shift_one & shift_eight) ^ y_word ^ shift_two;
        
        // Feistel Cross
        y_word = x_word;
        
        // XOR with Round Key
        x_word = temp ^ *(round_key_ptr + i);
    }
    // Assemble Plaintext Output Array   
    *word_ptr = x_word;
    *(word_ptr + 1) = y_word;
    return;
}
void simon_decrypt96(uint8_t round_limit, uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext){
    const uint8_t word_size = 48;
    bword_48 intrd = *(bword_48 *)ciphertext;
    uint64_t x_word = intrd.data;
    intrd = *((bword_48 *)(ciphertext+6));
    uint64_t y_word = intrd.data;

    int8_t i;
    for(i = round_limit - 1; i >= 0; i--) {  

        // Shift, AND , XOR ops
        uint64_t temp = (shift_one & shift_eight) ^ y_word ^ shift_two;

        // Feistel Cross
        y_word = x_word;
        
        // XOR with Round Key
        x_word = (temp ^ (*((bword_48 *)(key_schedule + (i*6)))).data) & 0xFFFFFFFFFFFF;
    }
    // Assemble Plaintext Output Array
    intrd.data = x_word;
    bword_48 * intrd_ptr = (bword_48 *)plaintext; 
    *intrd_ptr = intrd;
    
    intrd.data = y_word;
    intrd_ptr = (bword_48 *)(plaintext + 6);
    *intrd_ptr = intrd;
    return;
}
void simon_decrypt128(uint8_t round_limit, uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext){
    const uint8_t word_size = 64;
    uint64_t x_word = *(uint64_t *)ciphertext;
    uint64_t y_word = *(((uint64_t *)ciphertext) + 1);
    uint64_t *round_key_ptr = (uint64_t *)key_schedule;
    uint64_t *word_ptr = (uint64_t *)plaintext;

    int8_t i;
    for(i = round_limit - 1; i >=0; i--) {

        // Shift, AND , XOR ops
        uint64_t temp = (shift_one & shift_eight) ^ y_word ^ shift_two;
        
        // Feistel Cross
        y_word = x_word;
        
        // XOR with Round Key
        x_word = temp ^ *(round_key_ptr + i);
    }
    // Assemble Plaintext Output Array   
    *word_ptr = x_word;
    *(word_ptr + 1) = y_word;
    return;
}
