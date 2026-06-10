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
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <gmssl/sct.h>
#include <gmssl/tls.h>
#include <gmssl/oid.h>
#include <gmssl/digest.h>
#include <gmssl/error.h>


int sct_signed_data_to_bytes(int version, uint64_t timestamp, int entry_type,
	const uint8_t issuer_key_hash[SCT_ISSUER_KEY_HASH_SIZE],
	const uint8_t *entry, size_t entry_len,
	const uint8_t *exts, size_t extslen,
	uint8_t **out, size_t *outlen)
{
	if (version < 0 || version > 0xff
		|| !entry || !entry_len || entry_len > 0xffffff
		|| extslen > 0xffff || (extslen && !exts) || !outlen) {
		error_print();
		return -1;
	}
	switch (entry_type) {
	case SCT_log_entry_type_x509_entry:
		break;
	case SCT_log_entry_type_precert_entry:
		if (!issuer_key_hash) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	tls_uint8_to_bytes((uint8_t)version, out, outlen);
	tls_uint8_to_bytes(SCT_signature_type_certificate_timestamp, out, outlen);
	tls_uint64_to_bytes(timestamp, out, outlen);
	tls_uint16_to_bytes((uint16_t)entry_type, out, outlen);
	switch (entry_type) {
	case SCT_log_entry_type_x509_entry:
		tls_uint24array_to_bytes(entry, entry_len, out, outlen);
		break;
	case SCT_log_entry_type_precert_entry:
		tls_array_to_bytes(issuer_key_hash, SCT_ISSUER_KEY_HASH_SIZE,
			out, outlen);
		tls_uint24array_to_bytes(entry, entry_len, out, outlen);
		break;
	}
	tls_uint16array_to_bytes(exts, extslen, out, outlen);
	return 1;
}

int sct_signed_data_construct(const uint8_t *sct, size_t sct_len,
	int entry_type, const uint8_t issuer_key_hash[SCT_ISSUER_KEY_HASH_SIZE],
	const uint8_t *entry, size_t entry_len,
	uint8_t **out, size_t *outlen)
{
	int version;
	const uint8_t *log_id;
	uint64_t timestamp;
	const uint8_t *exts;
	size_t extslen;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;

	if (!sct || !sct_len || !entry || !entry_len || !outlen) {
		error_print();
		return -1;
	}
	if (signed_certificate_timestamp_from_bytes(&version, &log_id, &timestamp,
		&exts, &extslen, &sig_alg, &sig, &siglen, &sct, &sct_len) != 1
		|| sct_len) {
		error_print();
		return -1;
	}
	if (sct_signed_data_to_bytes(version, timestamp, entry_type,
		issuer_key_hash, entry, entry_len, exts, extslen,
		out, outlen) != 1) {
		error_print();
		return -1;
	}
	(void)log_id;
	(void)sig_alg;
	(void)sig;
	(void)siglen;
	return 1;
}

int signed_certificate_timestamp_signature_to_bytes(
	int sig_alg, const uint8_t *sig, size_t siglen,
	uint8_t **out, size_t *outlen)
{
	if (tls_signature_scheme_algorithm_oid(sig_alg) == OID_undef
		|| siglen > 0xffff
		|| (siglen && !sig) || !outlen) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes((uint16_t)sig_alg, out, outlen);
	tls_uint16array_to_bytes(sig, siglen, out, outlen);
	return 1;
}

int signed_certificate_timestamp_signature_from_bytes(
	int *sig_alg, const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen)
{
	uint16_t scheme;

	if (!sig_alg || !sig || !siglen || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&scheme, in, inlen) != 1
		|| tls_uint16array_from_bytes(sig, siglen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	*sig_alg = scheme;
	return 1;
}

int signed_certificate_timestamp_signature_print(FILE *fp, int fmt, int ind,
	const char *label, const uint8_t *d, size_t dlen)
{
	int sig_alg;
	const char *sig_alg_name;
	const uint8_t *sig;
	size_t siglen;

	if (!fp || !label || !d) {
		error_print();
		return -1;
	}
	if (signed_certificate_timestamp_signature_from_bytes(&sig_alg, &sig,
		&siglen, &d, &dlen) != 1 || dlen) {
		error_print();
		return -1;
	}

	sig_alg_name = tls_signature_scheme_name(sig_alg);
	format_print(fp, fmt, ind, "%s\n", label);
	format_print(fp, fmt, ind + 4, "sig_algorithm: %s (%04x)\n",
		sig_alg_name ? sig_alg_name : "unknown", sig_alg);
	format_bytes(fp, fmt, ind + 4, "signature", sig, siglen);
	return 1;
}

int signed_certificate_timestamp_to_bytes(int version,
	const uint8_t log_id[SCT_LOG_ID_SIZE], uint64_t timestamp,
	const uint8_t *exts, size_t extslen,
	int sig_alg, const uint8_t *sig, size_t siglen,
	uint8_t **out, size_t *outlen)
{
	if (version < 0 || version > 0xff || !log_id || extslen > 0xffff
		|| (extslen && !exts) || siglen > 0xffff || (siglen && !sig)
		|| tls_signature_scheme_algorithm_oid(sig_alg) == OID_undef
		|| !outlen) {
		error_print();
		return -1;
	}
	tls_uint8_to_bytes((uint8_t)version, out, outlen);
	tls_array_to_bytes(log_id, SCT_LOG_ID_SIZE, out, outlen);
	tls_uint64_to_bytes(timestamp, out, outlen);
	tls_uint16array_to_bytes(exts, extslen, out, outlen);
	if (signed_certificate_timestamp_signature_to_bytes(sig_alg, sig, siglen,
		out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int signed_certificate_timestamp_from_bytes(int *version,
	const uint8_t **log_id, uint64_t *timestamp,
	const uint8_t **exts, size_t *extslen,
	int *sig_alg, const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen)
{
	uint8_t ver;

	if (!version || !log_id || !timestamp || !exts || !extslen
		|| !sig_alg || !sig || !siglen || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (tls_uint8_from_bytes(&ver, in, inlen) != 1
		|| tls_array_from_bytes(log_id, SCT_LOG_ID_SIZE, in, inlen) != 1
		|| tls_uint64_from_bytes(timestamp, in, inlen) != 1
		|| tls_uint16array_from_bytes(exts, extslen, in, inlen) != 1
		|| signed_certificate_timestamp_signature_from_bytes(sig_alg, sig,
			siglen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	*version = ver;
	return 1;
}

int signed_certificate_timestamp_print(FILE *fp, int fmt, int ind,
	const char *label, const uint8_t *d, size_t dlen)
{
	int version;
	const uint8_t *log_id;
	uint64_t timestamp;
	const uint8_t *exts;
	size_t extslen;
	int sig_alg;
	const char *sig_alg_name;
	const uint8_t *sig;
	size_t siglen;

	if (!fp || !label || !d) {
		error_print();
		return -1;
	}
	if (signed_certificate_timestamp_from_bytes(&version, &log_id, &timestamp,
		&exts, &extslen, &sig_alg, &sig, &siglen, &d, &dlen) != 1
		|| dlen) {
		error_print();
		return -1;
	}

	sig_alg_name = tls_signature_scheme_name(sig_alg);
	format_print(fp, fmt, ind, "%s\n", label);
	format_print(fp, fmt, ind + 4, "version: %d\n", version);
	format_bytes(fp, fmt, ind + 4, "log_id", log_id, SCT_LOG_ID_SIZE);
	format_print(fp, fmt, ind + 4, "timestamp: %" PRIu64 "\n", timestamp);
	format_bytes(fp, fmt, ind + 4, "extensions", exts, extslen);
	format_print(fp, fmt, ind + 4, "sig_algorithm: %s (%04x)\n",
		sig_alg_name ? sig_alg_name : "unknown", sig_alg);
	format_bytes(fp, fmt, ind + 4, "signature", sig, siglen);
	return 1;
}

int signed_certificate_timestamp_verify(const uint8_t *sct, size_t sct_len,
	const uint8_t *signed_data, size_t signed_data_len,
	X509_KEY *key, const DIGEST *digest)
{
	int version;
	const uint8_t *log_id;
	uint64_t timestamp;
	const uint8_t *exts;
	size_t extslen;
	int sig_alg;
	int sig_alg_oid;
	const uint8_t *sig;
	size_t siglen;
	uint8_t dgst[DIGEST_MAX_SIZE];
	size_t dgstlen;
	X509_SIGN_CTX verify_ctx;

	if (!sct || !sct_len || !signed_data || !signed_data_len
		|| !key || !digest) {
		error_print();
		return -1;
	}
	if (signed_certificate_timestamp_from_bytes(&version, &log_id, &timestamp,
		&exts, &extslen, &sig_alg, &sig, &siglen, &sct, &sct_len) != 1
		|| sct_len) {
		error_print();
		return -1;
	}
	if (version != SCT_version_v1) {
		error_print();
		return -1;
	}

	if (x509_public_key_digest_ex(key, digest, dgst, &dgstlen) != 1
		|| dgstlen != SCT_LOG_ID_SIZE) {
		error_print();
		return -1;
	}
	if (memcmp(log_id, dgst, SCT_LOG_ID_SIZE) != 0) {
		error_print();
		return -1;
	}

	sig_alg_oid = tls_signature_scheme_algorithm_oid(sig_alg);
	if (sig_alg_oid == OID_undef) {
		error_print();
		return -1;
	}
	if (x509_verify_init(&verify_ctx, key, NULL, 0, sig, siglen) != 1
		|| verify_ctx.sign_algor != sig_alg_oid
		|| x509_verify_update(&verify_ctx, signed_data, signed_data_len) != 1
		|| x509_verify_finish(&verify_ctx) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sct_list_verify(const uint8_t *sct_list, size_t sct_list_len,
	int entry_type, const uint8_t issuer_key_hash[SCT_ISSUER_KEY_HASH_SIZE],
	const uint8_t *entry, size_t entry_len,
	const CT_LOG_INFO *ct_logs, size_t ct_logs_cnt,
	size_t at_least)
{
	const uint8_t *serialized_scts;
	size_t serialized_scts_len;
	size_t success_count = 0;
	size_t i;

	if (!sct_list || !sct_list_len || !entry || !entry_len
		|| !ct_logs || !ct_logs_cnt || !at_least
		|| at_least > ct_logs_cnt) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(&serialized_scts, &serialized_scts_len,
		&sct_list, &sct_list_len) != 1 || sct_list_len) {
		error_print();
		return -1;
	}

	for (i = 0; i < ct_logs_cnt; i++) {
		const uint8_t *scts = serialized_scts;
		size_t scts_len = serialized_scts_len;

		while (scts_len) {
			const uint8_t *sct;
			size_t sct_len;
			int version;
			const uint8_t *log_id;
			uint64_t timestamp;
			const uint8_t *exts;
			size_t extslen;
			int sig_alg;
			int sig_alg_oid;
			const uint8_t *sig;
			size_t siglen;
			uint8_t signed_data[SCT_MAX_SIGNED_DATA_SIZE];
			uint8_t *p = signed_data;
			size_t signed_data_len = 0;
			X509_SIGN_CTX verify_ctx;

			if (tls_uint16array_from_bytes(&sct, &sct_len,
				&scts, &scts_len) != 1) {
				error_print();
				return -1;
			}
			if (signed_certificate_timestamp_from_bytes(&version, &log_id,
				&timestamp, &exts, &extslen, &sig_alg, &sig, &siglen,
				&sct, &sct_len) != 1 || sct_len) {
				error_print();
				return -1;
			}
			if (version != SCT_version_v1
				|| memcmp(log_id, ct_logs[i].log_id, SCT_LOG_ID_SIZE) != 0) {
				continue;
			}

			sig_alg_oid = tls_signature_scheme_algorithm_oid(sig_alg);
			if (sig_alg_oid == OID_undef) {
				continue;
			}
			if (sct_signed_data_to_bytes(version, timestamp, entry_type,
				issuer_key_hash, entry, entry_len, exts, extslen,
				NULL, &signed_data_len) != 1) {
				error_print();
				return -1;
			}
			if (signed_data_len > sizeof(signed_data)) {
				error_print();
				return -1;
			}
			signed_data_len = 0;
			if (sct_signed_data_to_bytes(version, timestamp, entry_type,
				issuer_key_hash, entry, entry_len, exts, extslen,
				&p, &signed_data_len) != 1) {
				error_print();
				return -1;
			}

			if (x509_verify_init(&verify_ctx, &ct_logs[i].log_key,
				NULL, 0, sig, siglen) == 1
				&& verify_ctx.sign_algor == sig_alg_oid
				&& x509_verify_update(&verify_ctx,
					signed_data, signed_data_len) == 1
				&& x509_verify_finish(&verify_ctx) == 1) {
				success_count++;
				break;
			}
		}
		if (success_count >= at_least) {
			return 1;
		}
	}

	//error_print();
	return 0;
}
