/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_SM2_RECOVER_H
#define GMSSL_SM2_RECOVER_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sm3.h>

#ifdef __cplusplus
extern "C" {
#endif

int sm2_signature_to_public_key_points(const SM2_SIGNATURE *sig, const uint8_t dgst[32],
	SM2_POINT points[4], size_t *points_cnt);
int sm2_signature_conjugate(const SM2_SIGNATURE *sig, SM2_SIGNATURE *new_sig);

#ifdef __cplusplus
}
#endif
#endif
