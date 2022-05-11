/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm3.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>





// generate h1 in [1, n-1]
int sm9_hash1(sm9_bn_t h1, const char *id, size_t idlen, uint8_t hid)
{
	sm9_fn_t h;
	SM3_CTX ctx1;
	SM3_CTX ctx2;

	uint8_t prefix[1] = {0x01};
	uint8_t ct1[4] = {0x00, 0x00, 0x00, 0x01};
	uint8_t ct2[4] = {0x00, 0x00, 0x00, 0x02};
	uint8_t buf[64];

	sm3_init(&ctx1);
	sm3_update(&ctx1, prefix, sizeof(prefix));
	sm3_update(&ctx1, (uint8_t *)id, idlen);
	sm3_update(&ctx1, &hid, 1);
	ctx2 = ctx1;
	sm3_update(&ctx1, ct1, sizeof(ct1));
	sm3_update(&ctx2, ct2, sizeof(ct2));
	sm3_finish(&ctx1, buf);
	sm3_finish(&ctx2, buf + 32);

	// 这个buflen == 64，我们要将长为40的部分取出来，模 N-1  再加1
	return -1;
}

void sm9_fn_add(sm9_fn_t r, const sm9_fn_t a, const sm9_fn_t b)
{
}

void sm9_fn_sub(sm9_fn_t r, const sm9_fn_t a, const sm9_fn_t b)
{
}

void sm9_fn_mul(sm9_fn_t r, const sm9_fn_t a, const sm9_fn_t b)
{
}

void sm9_fn_inv(sm9_fn_t r, const sm9_fn_t a)
{
}

int sm9_fn_is_zero(const sm9_fn_t a)
{
	return 0;
}

int sm9_sign_master_key_generate(SM9_SIGN_MASTER_KEY *master)
{
	// k = rand(1, n-1)
	//sm9_bn_rand_range(master->ks, SM9_N);

	// Ppubs = k * P2 in E'(F_p^2)
	sm9_twist_point_mul_G(&master->Ppubs, master->ks);

	return 1;
}

int sm9_enc_master_key_generate(SM9_ENC_MASTER_KEY *master)
{
	// k = rand(1, n-1)
	//sm9_bn_rand_range(master->ke, SM9_N);

	// Ppube = ke * P1 in E(F_p)
	sm9_point_mul_generator(&master->Ppube, master->ke);

	return 1;
}

int sm9_sign_master_key_extract_key(SM9_SIGN_MASTER_KEY *master, const char *id, size_t idlen, SM9_SIGN_KEY *key)
{
	sm9_fn_t t;

	sm9_hash1(t, id, idlen, SM9_HID_SIGN);
	sm9_fn_add(t, t, master->ks);
	if (sm9_fn_is_zero(t)) {
		error_print();
		return -1;
	}
	sm9_fn_inv(t, t);
	sm9_fn_mul(t, t, master->ks);
	sm9_point_mul_generator(&key->ds, t);
	return 1;
}

int sm9_enc_master_key_extract_key(SM9_ENC_MASTER_KEY *master, const char *id, size_t idlen,
	SM9_ENC_KEY *key)
{
	sm9_fn_t t;

	sm9_hash1(t, id, idlen, SM9_HID_ENC);
	sm9_fn_add(t, t, master->ke);
	if (sm9_fn_is_zero(t)) {
		error_print();
		return -1;
	}
	sm9_fn_inv(t, t);
	sm9_fn_mul(t, t, master->ke);
	sm9_twist_point_mul_G(&key->de, t);
	return 1;
}









