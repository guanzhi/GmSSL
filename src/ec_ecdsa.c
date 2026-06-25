/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <string.h>
#include <gmssl/ecdsa.h>
#ifdef ENABLE_SECP256R1
#include <gmssl/secp256r1_ecdsa.h>
#endif
#ifdef ENABLE_SECP384R1
#include <gmssl/secp384r1_ecdsa.h>
#endif
#include <gmssl/error.h>


#ifdef ENABLE_SECP256R1
static int ecdsa_digest_to_p256(const uint8_t *dgst, size_t dgstlen, uint8_t out[32])
{
	if (!dgst || !out) {
		error_print();
		return -1;
	}
	if (dgstlen == 32) {
		memcpy(out, dgst, 32);
	} else if (dgstlen == 48) {
		memcpy(out, dgst, 32);
	} else {
		error_print();
		return -1;
	}
	return 1;
}
#endif

#ifdef ENABLE_SECP384R1
static int ecdsa_digest_to_p384(const uint8_t *dgst, size_t dgstlen, uint8_t out[48])
{
	if (!dgst || !out) {
		error_print();
		return -1;
	}
	if (dgstlen == 32) {
		memset(out, 0, 16);
		memcpy(out + 16, dgst, 32);
	} else if (dgstlen == 48) {
		memcpy(out, dgst, 48);
	} else {
		error_print();
		return -1;
	}
	return 1;
}
#endif

int ecdsa_sign(const EC_KEY *key, const uint8_t *dgst, size_t dgstlen,
	uint8_t *sig, size_t *siglen)
{
	if (!key || !dgst || !sig || !siglen) {
		error_print();
		return -1;
	}
	switch (key->oid) {
#ifdef ENABLE_SECP256R1
	case OID_secp256r1:
		{
			uint8_t e[32];
			if (ecdsa_digest_to_p256(dgst, dgstlen, e) != 1
				|| secp256r1_ecdsa_sign(&key->u.secp256r1_key, e, sig, siglen) != 1) {
				error_print();
				return -1;
			}
		}
		return 1;
#endif
#ifdef ENABLE_SECP384R1
	case OID_secp384r1:
		{
			uint8_t e[48];
			if (ecdsa_digest_to_p384(dgst, dgstlen, e) != 1
				|| secp384r1_ecdsa_sign(&key->u.secp384r1_key, e, sig, siglen) != 1) {
				error_print();
				return -1;
			}
		}
		return 1;
#endif
	default:
		error_print();
		return -1;
	}
}

int ecdsa_sign_fixed_len(const EC_KEY *key, const uint8_t *dgst, size_t dgstlen,
	size_t siglen, uint8_t *sig)
{
	if (!key || !dgst || !sig || !siglen) {
		error_print();
		return -1;
	}
	switch (key->oid) {
#ifdef ENABLE_SECP256R1
	case OID_secp256r1:
		{
			uint8_t e[32];
			if (ecdsa_digest_to_p256(dgst, dgstlen, e) != 1
				|| secp256r1_ecdsa_sign_fixlen(&key->u.secp256r1_key, e, siglen, sig) != 1) {
				error_print();
				return -1;
			}
		}
		return 1;
#endif
#ifdef ENABLE_SECP384R1
	case OID_secp384r1:
		{
			uint8_t e[48];
			if (ecdsa_digest_to_p384(dgst, dgstlen, e) != 1
				|| secp384r1_ecdsa_sign_fixlen(&key->u.secp384r1_key, e, siglen, sig) != 1) {
				error_print();
				return -1;
			}
		}
		return 1;
#endif
	default:
		error_print();
		return -1;
	}
}

int ecdsa_verify(const EC_KEY *key, const uint8_t *dgst, size_t dgstlen,
	const uint8_t *sig, size_t siglen)
{
	if (!key || !dgst || !sig || !siglen) {
		error_print();
		return -1;
	}
	switch (key->oid) {
#ifdef ENABLE_SECP256R1
	case OID_secp256r1:
		{
			uint8_t e[32];
			int ret;
			if (ecdsa_digest_to_p256(dgst, dgstlen, e) != 1) {
				error_print();
				return -1;
			}
			if ((ret = secp256r1_ecdsa_verify(&key->u.secp256r1_key, e, sig, siglen)) < 0) {
				error_print();
				return -1;
			}
			return ret;
		}
#endif
#ifdef ENABLE_SECP384R1
	case OID_secp384r1:
		{
			uint8_t e[48];
			int ret;
			if (ecdsa_digest_to_p384(dgst, dgstlen, e) != 1) {
				error_print();
				return -1;
			}
			if ((ret = secp384r1_ecdsa_verify(&key->u.secp384r1_key, e, sig, siglen)) < 0) {
				error_print();
				return -1;
			}
			return ret;
		}
#endif
	default:
		error_print();
		return -1;
	}
}
