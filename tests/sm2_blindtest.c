/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/sm2_blind.h>
#include <gmssl/error.h>


static int test_sm2_blind_sign(void)
{
	int r = -1;

	// signer
	SM2_KEY key;
	SM2_Fn k;
	uint8_t commit[65];
	size_t commitlen;

	// caller
	SM2_KEY public_key;
	SM2_BLIND_SIGN_CTX sign_ctx;
	uint8_t msg[128] = {0};
	uint8_t blinded_sig_s[32];
	uint8_t blinded_sig_r[32];
	uint8_t sig[128];
	size_t siglen;

	// verifier
	SM2_SIGN_CTX verify_ctx;


	// signer
	if (sm2_key_generate(&key) != 1
		|| sm2_key_set_public_key(&public_key, &key.public_key) != 1) {
		error_print();
		goto end;
	}
	if (sm2_blind_sign_commit(k, commit, &commitlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 0, "signer: commitment", commit, commitlen);

	// caller
	if (sm2_blind_sign_init(&sign_ctx, &public_key,
		SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1
		|| sm2_blind_sign_update(&sign_ctx, msg, 32) != 1
		|| sm2_blind_sign_update(&sign_ctx, msg + 32, 32) != 1
		|| sm2_blind_sign_update(&sign_ctx, msg + 64, 64) != 1
		|| sm2_blind_sign_finish(&sign_ctx, commit, commitlen, blinded_sig_r) != 1) {
		error_print();
		goto end;
	}
	format_bytes(stderr, 0, 0, "caller: blinded_sig_r", blinded_sig_r, sizeof(blinded_sig_r));

	// signer
	if (sm2_blind_sign(&key, k, blinded_sig_r, blinded_sig_s) != 1) {
		error_print();
		goto end;
	}
	format_bytes(stderr, 0, 0, "signer: blinded_sig_s", blinded_sig_s, sizeof(blinded_sig_s));

	// caller
	if (sm2_blind_sign_unblind(&sign_ctx, blinded_sig_s, sig, &siglen) != 1) {
		error_print();
		goto end;
	}
	format_bytes(stderr, 0, 0, "caller: unblinded_sig", sig, siglen);

	// verifier
	if (sm2_verify_init(&verify_ctx, &public_key,
		SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1
		|| sm2_verify_update(&verify_ctx, msg, sizeof(msg)) != 1
		|| (r = sm2_verify_finish(&verify_ctx, sig, siglen)) < 0) {
		error_print();
		goto end;
	}
	format_print(stderr, 0, 0, "verifier: %s\n", r == 1 ? "success" : "failure");

end:
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	return r;
}

int main(void)
{
	if (test_sm2_blind_sign() != 1) { error_print(); return -1; }
	return 0;
}
