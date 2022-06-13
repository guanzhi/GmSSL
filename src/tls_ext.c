/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
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


#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/tls.h>


#define TLS_EXTENSION_HEADER_SIZE 4

#if 0

int tls_exts_add(uint8_t *exts, size_t *extslen, size_t maxlen,
	int type, const uint8_t *data, size_t datalen)
{
	if (!exts || !extslen) {
		error_print();
		return -1;
	}
	if (datalen > TLS_MAX_PLAINTEXT_SIZE
		|| *extslen + TLS_EXTENSION_HEADER_SIZE + datalen > maxlen) {
		error_print();
		return -1;
	}
	exts += *extslen;
	tls_uint16_to_bytes(type, &exts, extslen);
	tls_uint16array_to_bytes(data, datalen, &exts, extslen);
	return 1;
}
#endif

int tls_exts_add_ec_point_formats(uint8_t *exts, size_t *extslen, size_t maxlen,
	const int *formats, size_t formats_cnt)
{
	int type = TLS_extension_ec_point_formats;
	size_t datalen = tls_uint8_size() + tls_uint8_size() * formats_cnt;
	size_t i;

	if (!exts || !extslen || !formats || !formats_cnt) {
		error_print();
		return -1;
	}
	if (formats_cnt > 256) {
		error_print();
		return -1;
	}
	if (*extslen + TLS_EXTENSION_HEADER_SIZE + datalen > maxlen) {
		error_print();
		return -1;
	}
	exts += *extslen;
	tls_uint16_to_bytes(type, &exts, extslen);
	tls_uint16_to_bytes(datalen, &exts, extslen);
	tls_uint8_to_bytes(tls_uint8_size() * formats_cnt, &exts, extslen);
	for (i = 0; i < formats_cnt; i++) {
		if (!tls_ec_point_format_name(formats[i])) {
			error_print();
			return -1;
		}
		tls_uint8_to_bytes(formats[i], &exts, extslen);
	}
	return 1;
}

#define TLS_MAX_SUPPORTED_GROUPS_COUNT 64

int tls_exts_add_supported_groups(uint8_t *exts, size_t *extslen, size_t maxlen,
	const int *curves, size_t curves_cnt)
{
	int type = TLS_extension_supported_groups;
	size_t datalen = tls_uint16_size() + tls_uint16_size() * curves_cnt;
	size_t i;

	if (!exts || !extslen || !curves || !curves_cnt) {
		error_print();
		return -1;
	}
	if (curves_cnt > TLS_MAX_SUPPORTED_GROUPS_COUNT) {
		error_print();
		return -1;
	}
	if (*extslen + TLS_EXTENSION_HEADER_SIZE + datalen > maxlen) {
		error_print();
		return -1;
	}
	exts += *extslen;
	tls_uint16_to_bytes(type, &exts, extslen);
	tls_uint16_to_bytes(datalen, &exts, extslen);
	tls_uint16_to_bytes(tls_uint16_size() * curves_cnt, &exts, extslen);
	for (i = 0; i < curves_cnt; i++) {
		tls_uint16_to_bytes(curves[i], &exts, extslen);
	}
	return 1;
}

#define TLS_MAX_SIGNATURE_ALGORS_COUNT 64

int tls_exts_add_signature_algors(uint8_t *exts, size_t *extslen, size_t maxlen,
	const int *algs, size_t algs_cnt)
{
	int type = TLS_extension_signature_algorithms;
	size_t datalen = tls_uint16_size() + tls_uint16_size() * algs_cnt;
	size_t i;

	if (!exts || !extslen || !algs || !algs_cnt) {
		error_print();
		return -1;
	}
	if (algs_cnt > TLS_MAX_SIGNATURE_ALGORS_COUNT) {
		error_print();
		return -1;
	}
	if (*extslen + TLS_EXTENSION_HEADER_SIZE + datalen > maxlen) {
		error_print();
		return -1;
	}
	exts += *extslen;
	tls_uint16_to_bytes(type, &exts, extslen);
	tls_uint16_to_bytes(datalen, &exts, extslen);
	tls_uint16_to_bytes(tls_uint16_size() * algs_cnt, &exts, extslen);
	for (i = 0; i < algs_cnt; i++) {
		tls_uint16_to_bytes(algs[i], &exts, extslen);
	}
	return 1;
}

int tls_process_client_ec_point_formats(const uint8_t *data, size_t datalen,
	uint8_t *exts, size_t *extslen, size_t maxlen)
{
	int shared_formats[] = { TLS_point_uncompressed };
	size_t shared_formats_cnt = 0;
	const uint8_t *p;
	size_t len;

	if (!data || !datalen || !exts || !extslen) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(&p, &len, &data, &datalen) != 1
		|| tls_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	while (len) {
		uint8_t format;
		if (tls_uint8_from_bytes(&format, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (!tls_ec_point_format_name(format)) {
			error_print();
			return -1;
		}
		if (format == shared_formats[0]) {
			shared_formats_cnt = 1;
		}
	}
	if (tls_exts_add_ec_point_formats(exts, extslen, maxlen, shared_formats, shared_formats_cnt) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_process_server_ec_point_formats(const uint8_t *data, size_t datalen)
{
	const uint8_t *p;
	size_t len;
	uint8_t format;

	if (tls_uint8array_from_bytes(&p, &len, &data, &datalen) != 1
		|| tls_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	if (tls_uint8_from_bytes(&format, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (format != TLS_point_uncompressed) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_process_client_signature_algors(const uint8_t *data, size_t datalen,
	uint8_t *exts, size_t *extslen, size_t maxlen)
{
	int shared_algs[1] = { TLS_sig_sm2sig_sm3 };
	size_t shared_algs_cnt = 0;
	const uint8_t *p;
	size_t len;

	if (!data || !datalen || !exts || !extslen) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(&p, &len, &data, &datalen) != 1
		|| tls_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	while (len) {
		uint16_t alg;
		if (tls_uint16_from_bytes(&alg, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (!tls_signature_scheme_name(alg)) {
			error_print();
			return -1;
		}
		if (alg == shared_algs[0]) {
			shared_algs_cnt = 1;
		}
	}
	if (tls_exts_add_signature_algors(exts, extslen, maxlen, shared_algs, shared_algs_cnt) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_process_server_signature_algors(const uint8_t *data, size_t datalen)
{
	const uint8_t *p;
	size_t len;
	uint16_t alg;

	if (tls_uint16array_from_bytes(&p, &len, &data, &datalen) != 1
		|| tls_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&alg, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (alg != TLS_sig_sm2sig_sm3) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_process_client_supported_groups(const uint8_t *data, size_t datalen, uint8_t *exts, size_t *extslen, size_t maxlen)
{
	int shared_curves[1] = { TLS_curve_sm2p256v1 };
	size_t shared_curves_cnt = 0;
	const uint8_t *p;
	size_t len;

	if (!data || !datalen || !exts || !extslen) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(&p, &len, &data, &datalen) != 1
		|| tls_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	while (len) {
		uint16_t curve;
		if (tls_uint16_from_bytes(&curve, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (!tls_named_curve_name(curve)) {
			error_print();
			return -1;
		}
		if (curve == shared_curves[0]) {
			shared_curves_cnt = 1;
		}
	}
	if (tls_exts_add_supported_groups(exts, extslen, maxlen, shared_curves, shared_curves_cnt) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_process_server_supported_groups(const uint8_t *data, size_t datalen)
{
	const uint8_t *p;
	size_t len;
	uint16_t curve;

	if (tls_uint16array_from_bytes(&p, &len, &data, &datalen) != 1
		|| tls_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&curve, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (curve != TLS_curve_sm2p256v1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_ext_from_bytes(int *type, const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen)
{
	uint16_t ext_type;
	if (tls_uint16_from_bytes(&ext_type, in, inlen) != 1
		|| tls_uint16array_from_bytes(data, datalen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	*type = ext_type;
	if (!tls_extension_name(ext_type)) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_process_client_exts(const uint8_t *exts, size_t extslen, uint8_t *out, size_t *outlen, size_t maxlen)
{
	int type;
	const uint8_t *data;
	size_t datalen;

	while (extslen) {
		if (tls_ext_from_bytes(&type, &data, &datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}

		switch (type) {
		case TLS_extension_ec_point_formats:
			if (tls_process_client_ec_point_formats(data, datalen, out, outlen, maxlen) != 1) {
				error_print();
				return -1;
			}
			break;
		case TLS_extension_signature_algorithms:
			if (tls_process_client_signature_algors(data, datalen, out, outlen, maxlen) != 1) {
				error_print();
				return -1;
			}
			break;
		case TLS_extension_supported_groups:
			if (tls_process_client_supported_groups(data, datalen, out, outlen, maxlen) != 1) {
				error_print();
				return -1;
			}
			break;
		default:
			error_print();
			return -1;
		}
	}
	return 1;
}

int tls_process_server_exts(const uint8_t *exts, size_t extslen,
	int *ec_point_format, int *supported_group, int *signature_algor)
{
	int type;
	const uint8_t *data;
	size_t datalen;

	*ec_point_format = -1;
	*supported_group = -1;
	*signature_algor = -1;

	while (extslen) {
		if (tls_ext_from_bytes(&type, &data, &datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}

		switch (type) {
		case TLS_extension_ec_point_formats:
			if (tls_process_server_ec_point_formats(data, datalen) != 1) {
				error_print();
				return -1;
			}
			*ec_point_format = TLS_point_uncompressed;
			break;
		case TLS_extension_signature_algorithms:
			if (tls_process_server_signature_algors(data, datalen) != 1) {
				error_print();
				return -1;
			}
			*supported_group = TLS_curve_sm2p256v1;
			break;
		case TLS_extension_supported_groups:
			if (tls_process_server_supported_groups(data, datalen) != 1) {
				error_print();
				return -1;
			}
			*signature_algor = TLS_sig_sm2sig_sm3;
			break;
		default:
			error_print();
			return -1;
		}
	}
	return 1;
}
