/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/mem.h>
#include <gmssl/tls.h>

#include <errno.h>
#ifndef WIN32
#include <fcntl.h>
#include <sys/select.h>
#endif


/*
ClientHello.exts.signed_certificate_timestamp
	ext_data := empty
*/


/*
Certificate.certificate_list.CertificateEntry.exts.signed_certificate_timestamp
	ext_data := SignedCertificateTimestamp sct_list<0..2^16-1>;
	struct {
		opaque key_id[32];
		uint64 timestamp;
		opaque signature<0..2^16-1>;
	} SignedCertificateTimestamp;
*/

int tls_signed_certificate_timestamp_entry_to_bytes(const uint8_t key_id[32],
	uint64_t timestamp, const uint8_t *signature, size_t signature_len,
	uint8_t **out, size_t *outlen)
{
	if (!key_id || !signature || !signature_len || !outlen) {
		error_print();
		return -1;
	}

	tls_array_to_bytes(key_id, 32, out, outlen);
	tls_uint64_to_bytes(timestamp, out, outlen);
	tls_uint16array_to_bytes(signature, signature_len, out, outlen);
	return 1;
}

int tls_signed_certificate_timestamp_entry_from_bytes(const uint8_t **key_id,
	uint64_t *timestamp, const uint8_t **signature, size_t *signature_len,
	const uint8_t **in, size_t *inlen)
{
	if (!key_id || !timestamp || !signature || !signature_len || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (tls_array_from_bytes(key_id, 32, in, inlen) != 1
		|| tls_uint64_from_bytes(timestamp, in, inlen) != 1
		|| tls_uint16array_from_bytes(signature, signature_len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_signed_certificate_timestamp_ext_to_bytes(const uint8_t *sct_list, size_t sct_list_len,
	uint8_t **out, size_t *outlen)
{
	if (!sct_list || !sct_list_len || !outlen) {
		error_print();
		return -1;
	}
	tls_uint16array_to_bytes(sct_list, sct_list_len, out, outlen);
	return 1;
}

int tls_signed_certificate_timestamp_from_bytes(const uint8_t **sct_list, size_t *sct_list_len,
	const uint8_t **in, size_t *inlen)
{
	if (!sct_list || !sct_list_len || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(sct_list, sct_list_len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_signed_certificate_timestamp_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	const uint8_t *sct_list;
	size_t sct_list_len;

	if (tls_uint16array_from_bytes(&sct_list, &sct_list_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "sct_list\n");
	ind += 4;

	if (!sct_list_len) {
		format_print(fp, fmt, ind, "(null)\n");
	}
	while (sct_list_len) {
		const uint8_t *key_id;
		uint64_t timestamp;
		const uint8_t *signature;
		size_t signature_len;
		int entry_ind = ind + 4;

		format_print(fp, fmt, ind, "SignedCertificateTimestamp\n");

		if (tls_array_from_bytes(&key_id, 32, &sct_list, &sct_list_len) != 1
			|| tls_uint64_from_bytes(&timestamp, &sct_list, &sct_list_len) != 1
			|| tls_uint16array_from_bytes(&signature, &signature_len, &sct_list, &sct_list_len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(fp, fmt, entry_ind, "key_id", key_id, 32);
		format_print(fp, fmt, entry_ind, "timestamp: %"PRIu64"\n", timestamp);
		format_bytes(fp, fmt, entry_ind, "signature", signature, signature_len);
		if (dlen) {
			error_print();
			return -1;
		}
	}
	return 1;
}

// 这个应该改为enable, 服务器也可以设定是否响应这个请求
int tls_enable_signed_certificate_timestamp(TLS_CONNECT *conn)
{
	if (!conn) {
		error_print();
		return -1;
	}
	conn->signed_certificate_timestamp = 1;
	return 1;
}

int tls_ctx_enable_signed_certificate_timestamp(TLS_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	ctx->signed_certificate_timestamp = 1;
	return 1;
}


int tls13_signed_certificate_timestamp_verify(const uint8_t *sct_list, size_t sct_list_len)
{
	//error_print();
	return 1;
}



