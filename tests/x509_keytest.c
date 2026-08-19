/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/oid.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_key.h>
#include <gmssl/sm2.h>
#include <gmssl/ec.h>
#include <gmssl/asn1.h>


#ifdef ENABLE_LMS
static int lms_types[] = {
	LMS_SM3_M32_H5,
	LMS_SM3_M32_H5,
	LMS_SM3_M32_H5,
};
#endif

struct {
	int algor;
	int algor_param;
} tests[] = {
	{ OID_ec_public_key, OID_sm2 },
#ifdef ENABLE_SECP256R1
	{ OID_ec_public_key, OID_secp256r1 },
#endif
#ifdef ENABLE_SECP384R1
	{ OID_ec_public_key, OID_secp384r1 },
#endif
#ifdef ENABLE_LMS
	{ OID_lms_hashsig, LMS_SM3_M32_H5 },
	{ OID_hss_lms_hashsig, OID_undef }, // use lms_types[]
#endif
#ifdef ENABLE_XMSS
	{ OID_xmss_hashsig, XMSS_SM3_10_256 },
	{ OID_xmssmt_hashsig, XMSSMT_SM3_20_4_256 },
#endif
#ifdef ENABLE_SPHINCS
	{ OID_sphincs_hashsig, OID_undef },
#endif
#ifdef ENABLE_KYBER
	{ OID_kyber_kem, OID_undef },
#endif
};

X509_KEY x509_keys[sizeof(tests)/sizeof(tests[0])];


static int test_sign_algor(const X509_KEY *key)
{
	switch (key->algor) {
	case OID_ec_public_key:
		switch (key->algor_param) {
		case OID_sm2:
			return OID_sm2sign_with_sm3;
#ifdef ENABLE_SECP256R1
		case OID_secp256r1:
			return OID_ecdsa_with_sha256;
#endif
		default:
			return OID_undef;
		}
#ifdef ENABLE_LMS
	case OID_lms_hashsig:
	case OID_hss_lms_hashsig:
		return key->algor;
#endif
#ifdef ENABLE_XMSS
	case OID_xmss_hashsig:
	case OID_xmssmt_hashsig:
		return key->algor;
#endif
#ifdef ENABLE_SPHINCS
	case OID_sphincs_hashsig:
		return key->algor;
#endif
	default:
		return OID_undef;
	}
}


static int test_x509_public_key_algor_sm2_oid(void)
{
	// Test 1: Search sm2 in public key list
	{
		const char *name = x509_public_key_algor_name(OID_sm2);
		if (name == NULL || strcmp(name, "sm2") != 0) {
			error_print();
			return -1;
		}
		int oid = x509_public_key_algor_from_name("sm2");
		if (oid != OID_sm2) {
			error_print();
			return -1;
		}
	}

	// Test 2: Construct a sm2 algo der, parse it
	{
		uint8_t buf[256];
		const uint8_t *cp = buf;

		// SEQUENCE { OID 1.2.156.10197.1.301, OID 1.2.156.10197.1.301 }
		static const uint8_t sm2_algor_der[] = {
			0x30, 0x14,
			0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d,
			0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d,
		};
		memcpy(buf, sm2_algor_der, sizeof(sm2_algor_der));
		size_t len = sizeof(sm2_algor_der);

		int oid = 0;
		int curve = 0;
		if (x509_public_key_algor_from_der(&oid, &curve, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (oid != OID_sm2) {
			error_print();
			return -1;
		}
		if (curve != OID_sm2) {
			error_print();
			return -1;
		}
		if (len != 0) {
			error_print();
			return -1;
		}
	}

	// Test 3: Build a full SM2-OID SubjectPublicKeyInfo, parse it with
	//         sm2_public_key_info_from_der, and verify the key matches.
	{
		SM2_KEY sm2_key;
		uint8_t pubkey_der[256];
		uint8_t spki_der[512];

		if (sm2_key_generate(&sm2_key) != 1) {
			error_print();
			return -1;
		}

		// sm2_public_key_to_der already produces a BIT STRING (tag 0x03)
		// wrapping the EC point, so we use it directly as the second
		// element of SubjectPublicKeyInfo.
		uint8_t *pkp = pubkey_der;
		size_t pklen = 0;
		if (sm2_public_key_to_der(&sm2_key, &pkp, &pklen) != 1) {
			error_print();
			return -1;
		}

		// Build SubjectPublicKeyInfo manually with sm2 OID format:
		// SEQUENCE {
		//   SEQUENCE { OID sm2, OID sm2 }   <- AlgorithmIdentifier
		//   BIT STRING { ECPoint }          <- from sm2_public_key_to_der
		// }
		static const uint8_t sm2_alg[] = {
			0x30, 0x14,
			0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d,
			0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d,
		};
		size_t alg_len = sizeof(sm2_alg);
		size_t inner_len = alg_len + pklen;

		uint8_t *p = spki_der;
		// SEQUENCE header
		*p++ = 0x30;
		if (inner_len < 0x80) {
			*p++ = (uint8_t)inner_len;
		} else {
			*p++ = 0x81;
			*p++ = (uint8_t)inner_len;
		}
		// Algorithm identifier (sm2 OID format)
		memcpy(p, sm2_alg, alg_len);
		p += alg_len;
		// BIT STRING from sm2_public_key_to_der
		memcpy(p, pubkey_der, pklen);
		p += pklen;
		size_t spki_len = p - spki_der;

		// Parse it back
		SM2_KEY parsed_key;
		const uint8_t *cp2 = spki_der;
		if (sm2_public_key_info_from_der(&parsed_key, &cp2, &spki_len) != 1) {
			error_print();
			return -1;
		}
		if (spki_len != 0) {
			error_print();
			return -1;
		}
		if (sm2_public_key_equ(&sm2_key, &parsed_key) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_public_key_algor_sm2_to_der(void)
{
	// Test 4: Verify x509_public_key_algor_to_der(OID_sm2, OID_sm2)
	// produces GM/T 0015-2023 SM2-OID format (algorithm OID = sm2),
	// while x509_public_key_algor_to_der(OID_ec_public_key, OID_sm2)
	// produces RFC 5480 format (algorithm OID = id-ecPublicKey).
	{
		uint8_t der_sm2[64];
		uint8_t der_ec[64];
		uint8_t *p_sm2 = der_sm2;
		uint8_t *p_ec = der_ec;
		size_t len_sm2 = 0;
		size_t len_ec = 0;

		if (x509_public_key_algor_to_der(OID_sm2, OID_sm2, &p_sm2, &len_sm2) != 1) {
			error_print();
			return -1;
		}
		if (x509_public_key_algor_to_der(OID_ec_public_key, OID_sm2, &p_ec, &len_ec) != 1) {
			error_print();
			return -1;
		}
		// SM2-OID format and id-ecPublicKey format should produce different DER
		if (len_sm2 == len_ec && memcmp(der_sm2, der_ec, len_sm2) == 0) {
			error_print();
			return -1;
		}
		// Verify SM2-OID output starts with SEQUENCE { OID 1.2.156.10197.1.301
		static const uint8_t sm2_oid_prefix[] = {
			0x30, 0x14,
			0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d,
		};
		if (len_sm2 < sizeof(sm2_oid_prefix)
			|| memcmp(der_sm2, sm2_oid_prefix, sizeof(sm2_oid_prefix)) != 0) {
			error_print();
			return -1;
		}
		// Verify id-ecPublicKey output starts with SEQUENCE { OID 1.2.840.10045.2.1
		static const uint8_t ec_oid_prefix[] = {
			0x30, 0x13,
			0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
		};
		if (len_ec < sizeof(ec_oid_prefix)
			|| memcmp(der_ec, ec_oid_prefix, sizeof(ec_oid_prefix)) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_public_key_info_sm2_oid_from_der(void)
{
	// Test 5: Build a full SM2-OID SubjectPublicKeyInfo and parse it with
	//         the generic x509_public_key_info_from_der, verifying that
	//         algor is normalized to OID_sm2 and algor_param to OID_sm2.
	{
		SM2_KEY sm2_key;
		uint8_t pubkey_der[256];
		uint8_t spki_der[512];

		if (sm2_key_generate(&sm2_key) != 1) {
			error_print();
			return -1;
		}

		uint8_t *pkp = pubkey_der;
		size_t pklen = 0;
		if (sm2_public_key_to_der(&sm2_key, &pkp, &pklen) != 1) {
			error_print();
			return -1;
		}

		// Build SubjectPublicKeyInfo with SM2-OID format:
		// SEQUENCE {
		//   SEQUENCE { OID sm2, OID sm2 }   <- GM/T 0015-2023 format
		//   BIT STRING { ECPoint }
		// }
		static const uint8_t sm2_alg[] = {
			0x30, 0x14,
			0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d,
			0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d,
		};
		size_t alg_len = sizeof(sm2_alg);
		size_t inner_len = alg_len + pklen;

		uint8_t *p = spki_der;
		*p++ = 0x30;
		if (inner_len < 0x80) {
			*p++ = (uint8_t)inner_len;
		} else {
			*p++ = 0x81;
			*p++ = (uint8_t)inner_len;
		}
		memcpy(p, sm2_alg, alg_len);
		p += alg_len;
		memcpy(p, pubkey_der, pklen);
		p += pklen;
		size_t spki_len = p - spki_der;

		// Parse with generic x509_public_key_info_from_der
		X509_KEY parsed_key;
		const uint8_t *cp = spki_der;
		if (x509_public_key_info_from_der(&parsed_key, &cp, &spki_len) != 1) {
			error_print();
			return -1;
		}
		if (spki_len != 0) {
			error_print();
			return -1;
		}
		if (parsed_key.algor != OID_sm2) {
			error_print();
			return -1;
		}
		if (parsed_key.algor_param != OID_sm2) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_private_key_info_sm2_oid_from_der(void)
{
	// Test 6: Parse a GM/T 0015-2023 SM2-OID PrivateKeyInfo. The parsed
	// X509_KEY must keep algor = OID_sm2 (no normalization to
	// OID_ec_public_key), and must compare equal to the same key parsed
	// from an SM2-OID SubjectPublicKeyInfo.
	{
		X509_KEY key;
		uint8_t pki[512];
		uint8_t *p = pki;
		size_t pki_len = 0;
		const uint8_t *attrs;
		size_t attrslen;

		int param = OID_sm2;
		if (x509_key_generate(&key, OID_sm2, &param, sizeof(param)) != 1) {
			error_print();
			return -1;
		}
		if (x509_private_key_info_to_der(&key, &p, &pki_len) != 1) {
			error_print();
			return -1;
		}

		X509_KEY parsed_key;
		const uint8_t *cp = pki;
		size_t len = pki_len;
		if (x509_private_key_info_from_der(&parsed_key, &attrs, &attrslen, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != 0) {
			error_print();
			return -1;
		}
		if (parsed_key.algor != OID_sm2) {
			error_print();
			return -1;
		}
		if (parsed_key.algor_param != OID_sm2) {
			error_print();
			return -1;
		}

		// The same key parsed from an SM2-OID SubjectPublicKeyInfo must
		// compare equal to the parsed private key.
		uint8_t spki_der[512];
		uint8_t *p2 = spki_der;
		size_t spki_len = 0;
		if (x509_public_key_info_to_der(&key, &p2, &spki_len) != 1) {
			error_print();
			return -1;
		}
		X509_KEY parsed_pub;
		const uint8_t *cp2 = spki_der;
		size_t len2 = spki_len;
		if (x509_public_key_info_from_der(&parsed_pub, &cp2, &len2) != 1) {
			error_print();
			return -1;
		}
		if (x509_public_key_equ(&parsed_key, &parsed_pub) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_key_generate(void)
{
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		void *param = NULL;
		size_t paramlen = 0;

		switch (tests[i].algor) {
#ifdef ENABLE_LMS
		case OID_hss_lms_hashsig:
			param = lms_types;
			paramlen = sizeof(lms_types);
			break;
#endif
#ifdef ENABLE_SPHINCS
		case OID_sphincs_hashsig:
#endif
#ifdef ENABLE_KYBER
		case OID_kyber_kem:
#endif
#if defined(ENABLE_SPHINCS) || defined(ENABLE_KYBER)
			param = NULL;
			paramlen = 0;
			break;
#endif
		default:
			param = &tests[i].algor_param;
			paramlen = sizeof(tests[i].algor_param);
		}
		if (x509_key_generate(&x509_keys[i], tests[i].algor, param, paramlen) != 1) {
			error_print();
			return -1;
		}
		//x509_private_key_print(stderr, 0, 4, "private_key", &x509_keys[i]);
		//x509_public_key_print(stderr, 0, 4, "private_key", &x509_keys[i]);
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_public_key_to_bytes(void)
{
	uint8_t buf[1568]; // kyber-1024
	uint8_t *p;
	size_t len;
	uint8_t dgst[32];
	int i;

	//format_print(stderr, 0, 4, "public_key_to_bytes size\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		p = buf;
		len = 0;
		if (x509_public_key_to_bytes(&x509_keys[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		//format_print(stderr, 0, 4, "%s: %zu\n", x509_public_key_algor_name(tests[i].algor), len);
		if (x509_public_key_digest(&x509_keys[i], dgst) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_public_key_info_to_der(void)
{
	X509_KEY key;
	uint8_t buf[2048];
	int i;

	//format_print(stderr, 0, 4, "public_key_info_to_bytes size\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		const uint8_t *cp = buf;
		uint8_t *p = buf;
		size_t len = 0;

		if (x509_public_key_info_to_der(&x509_keys[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		//format_print(stderr, 0, 8, "%s: %zu\n", x509_public_key_algor_name(tests[i].algor), len);

		if (x509_public_key_info_from_der(&key, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (len) {
			fprintf(stderr, "len = %zu\n", len);
			error_print();
			return -1;
		}

		if (x509_public_key_equ(&key, &x509_keys[i]) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_private_key_info_to_der(void)
{
	X509_KEY key;
	uint8_t buf[512];
	int i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]) && tests[i].algor == OID_ec_public_key; i++) {
		const uint8_t *cp = buf;
		uint8_t *p = buf;
		size_t len = 0;
		const uint8_t *attrs;
		size_t attrslen;

		if (x509_private_key_info_to_der(&x509_keys[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (x509_private_key_info_from_der(&key, &attrs, &attrslen, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (len) {
			error_print();
			return -1;
		}
		if (x509_public_key_equ(&key, &x509_keys[i]) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_private_key_info_encrypt_to_der(void)
{
	const char *pass = "P@ssw0rd";
	X509_KEY key;
	uint8_t buf[1024];
	int i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]) && tests[i].algor == OID_ec_public_key; i++) {
		const uint8_t *cp = buf;
		uint8_t *p = buf;
		size_t len = 0;
		const uint8_t *attrs;
		size_t attrslen;

		if (x509_private_key_info_encrypt_to_der(&x509_keys[i], pass, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (x509_private_key_info_decrypt_from_der(&key, &attrs, &attrslen, pass, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (len) {
			error_print();
			return -1;
		}
		if (x509_public_key_equ(&key, &x509_keys[i]) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_private_key_info_encrypt_to_pem(void)
{
	const char *pass = "P@ssw0rd";
	X509_KEY key;
	uint8_t buf[1024];
	FILE *fp;
	int i;


	for (i = 0; i < sizeof(tests)/sizeof(tests[0]) && tests[i].algor == OID_ec_public_key; i++) {
		const uint8_t *cp = buf;
		uint8_t *p = buf;
		size_t len = 0;
		const uint8_t *attrs;
		size_t attrslen;

		if (!(fp = tmpfile())) {
			error_print();
			return -1;
		}
		if (x509_private_key_info_encrypt_to_pem(&x509_keys[i], pass, fp) != 1) {
			error_print();
			fclose(fp);
			return -1;
		}
		rewind(fp);

		if (x509_private_key_info_decrypt_from_pem(&key, &attrs, &attrslen, pass, fp) != 1) {
			error_print();
			fclose(fp);
			return -1;
		}
		fclose(fp);
		if (len) {
			error_print();
			return -1;
		}
		if (x509_public_key_equ(&key, &x509_keys[i]) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_private_key_info_decrypt_from_pem(void)
{
	const char *pass = "P@ssw0rd";
	FILE *fp;
	int i;

	if (!(fp = tmpfile())) {
		error_print();
		return -1;
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]) && tests[i].algor == OID_ec_public_key; i++) {
		if (x509_private_key_info_encrypt_to_pem(&x509_keys[i], pass, fp) != 1) {
			error_print();
			fclose(fp);
			return -1;
		}

	}
	rewind(fp);
	while (1) {
		int ret;
		X509_KEY key;
		const uint8_t *attrs;
		size_t attrslen;

		if ((ret = x509_private_key_info_decrypt_from_pem(&key, &attrs, &attrslen, pass, fp)) < 0) {
			error_print();
			fclose(fp);
			return -1;
		} else if (ret == 0) {
			break;
		}
	}
	fclose(fp);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_sign(void)
{
	size_t i;
	X509_SIGN_CTX sign_ctx;
	void *args = NULL;
	size_t argslen = 0;
	uint8_t msg[66];
	uint8_t sig[40969];
	size_t siglen;

	memset(msg, 0xa5, sizeof(msg));

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		int sign_algor;

		if (tests[i].algor == OID_kyber_kem) {
			continue;
		}
		sign_algor = test_sign_algor(&x509_keys[i]);
		if (sign_algor == OID_undef) {
			continue;
		}
		//format_print(stderr, 0, 4, "%s\n", x509_public_key_algor_name(tests[i].algor));
		if (x509_sign_init(&sign_ctx, &x509_keys[i], sign_algor, args, argslen) != 1) {
			error_print();
			return -1;
		}
		if (x509_sign(&sign_ctx, msg, sizeof(msg), sig, &siglen) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s: %zu\n", x509_public_key_algor_name(tests[i].algor), siglen);
		if (x509_verify_init(&sign_ctx, &x509_keys[i], sign_algor, args, argslen, sig, siglen) != 1) {
			error_print();
			return -1;
		}
		if (x509_verify(&sign_ctx, msg, sizeof(msg)) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

#ifdef ENABLE_SM9
static int test_x509_sign_sm9(void)
{
	SM9_SIGN_MASTER_KEY sm9_sign_master_key;
	SM9_SIGN_KEY sm9_sign_key;
	char *id = "guan@pku.edu.cn";
	size_t idlen = strlen(id);
	X509_KEY x509_key;
	X509_SIGN_CTX sign_ctx;
	uint8_t msg[66];
	uint8_t sig[128]; // sm9 signature size = 104
	size_t siglen;

	if (sm9_sign_master_key_generate(&sm9_sign_master_key) != 1) {
		error_print();
		return -1;
	}
	if (sm9_sign_master_key_extract_key(&sm9_sign_master_key, id, idlen, &sm9_sign_key) != 1) {
		error_print();
		return -1;
	}

	if (x509_key_set_sm9_sign_key(&x509_key, &sm9_sign_key) != 1) {
		error_print();
		return -1;
	}
	if (x509_sign_init(&sign_ctx, &x509_key, OID_sm9sign, NULL, 0) != 1) {
		error_print();
		return -1;
	}
	if (x509_sign_update(&sign_ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (x509_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}

	if (x509_key_set_sm9_sign_master_key(&x509_key, &sm9_sign_master_key) != 1) {
		error_print();
		return -1;
	}
	if (x509_verify_init(&sign_ctx, &x509_key, OID_sm9sign, id, idlen, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	if (x509_verify_update(&sign_ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (x509_verify_finish(&sign_ctx) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
#endif

static int test_x509_key_exchange(void)
{
	X509_KEY key;
	uint8_t point1[65];
	uint8_t point2[65];
	uint8_t share1[32];
	uint8_t share2[32];
	uint8_t *p;
	size_t len;
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (tests[i].algor != OID_ec_public_key) {
			continue;
		}
		if (tests[i].algor_param == OID_secp384r1) {
			continue;
		}
		if (x509_key_generate(&key, tests[i].algor, &tests[i].algor_param, sizeof(tests[i].algor_param)) != 1) {
			error_print();
			return -1;
		}

		// export public key 1
		p = point1;
		len = 0;
		if (x509_public_key_to_bytes(&key, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != sizeof(point1)) {
			error_print();
			return -1;
		}

		// export public key 2
		p = point2;
		len = 0;
		if (x509_public_key_to_bytes(&x509_keys[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != sizeof(point2)) {
			error_print();
			return -1;
		}

		// key exchange 1
		if (x509_key_exchange(&key, point2, sizeof(point2), share1, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != sizeof(share1)) {
			error_print();
			return -1;
		}

		// key exchange 2
		if (x509_key_exchange(&x509_keys[i], point1, sizeof(point1), share2, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != sizeof(share2)) {
			error_print();
			return -1;
		}

		// share secrets equal
		if (memcmp(share1, share2, sizeof(share1)) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

#ifdef ENABLE_KYBER
static int test_x509_kem(void)
{
	uint8_t ciphertext[sizeof(KYBER_CIPHERTEXT)];
	size_t ciphertext_len;
	uint8_t secret1[32];
	uint8_t secret2[32];
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (tests[i].algor != OID_kyber_kem) {
			continue;
		}

		if (x509_key_encapsulate(&x509_keys[i], ciphertext, &ciphertext_len, secret1) != 1) {
			error_print();
			return -1;
		}
		if (ciphertext_len != sizeof(ciphertext)) {
			error_print();
			return -1;
		}
		if (x509_key_decapsulate(&x509_keys[i], ciphertext, ciphertext_len, secret2) != 1) {
			error_print();
			return -1;
		}
		if (memcmp(secret1, secret2, 32) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
#endif

int main(void)
{
	if (test_x509_public_key_algor_sm2_oid() != 1) goto err;
	if (test_x509_public_key_algor_sm2_to_der() != 1) goto err;
	if (test_x509_public_key_info_sm2_oid_from_der() != 1) goto err;
	if (test_x509_private_key_info_sm2_oid_from_der() != 1) goto err;
	if (test_x509_key_generate() != 1) goto err;
	if (test_x509_public_key_to_bytes() != 1) goto err;
	if (test_x509_public_key_info_to_der() != 1) goto err;
	if (test_x509_private_key_info_to_der() != 1) goto err;
	if (test_x509_private_key_info_encrypt_to_der() != 1) goto err;
	if (test_x509_private_key_info_encrypt_to_pem() != 1) goto err;
	if (test_x509_private_key_info_decrypt_from_pem() != 1) goto err;
	if (test_x509_sign() != 1) goto err;
#ifdef ENABLE_SM9
	if (test_x509_sign_sm9() != 1) goto err;
#endif
	if (test_x509_key_exchange() != 1) goto err;
#ifdef ENABLE_KYBER
	if (test_x509_kem() != 1) goto err;
#endif

	printf("%s all tests passed!\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
