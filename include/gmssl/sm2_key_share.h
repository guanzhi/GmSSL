/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

// SM2 Key Shamir Secret Sharing


#ifndef GMSSL_SM2_KEY_SHARE_H
#define GMSSL_SM2_KEY_SHARE_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sm2.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SM2_KEY_MAX_SHARES 12 // 12! = 479001600 < 2^31 = 2147483648


typedef struct {
	SM2_KEY key;
	size_t index;
	size_t total_cnt;
} SM2_KEY_SHARE;

int sm2_key_split(const SM2_KEY *key, size_t recover_cnt, size_t total_cnt, SM2_KEY_SHARE *shares);
int sm2_key_recover(SM2_KEY *key, const SM2_KEY_SHARE *shares, size_t shares_cnt);
int sm2_key_share_encrypt_to_file(const SM2_KEY_SHARE *share, const char *pass, const char *path_prefix);
int sm2_key_share_decrypt_from_file(SM2_KEY_SHARE *share, const char *pass, const char *file);
int sm2_key_share_print(FILE *fp, int fmt, int ind, const char *label, const SM2_KEY_SHARE *share);


#ifdef __cplusplus
}
#endif
#endif
