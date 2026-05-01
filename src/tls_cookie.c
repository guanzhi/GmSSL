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
cookie
	* server HelloRetryReqeust
	* client ClientHello (again)

struct {
	opaque cookie<1..2^16-1>;
} Cookie;

*/

int tls13_cookie_generate(const SM4_KEY *cookie_key, // server_ctx->cookie_key
	const uint8_t *client_info, size_t client_info_len,
	uint8_t *cookie, size_t *cookie_len)
{
	rand_bytes(cookie, 32);
	*cookie_len = 32;
	return 1;
}

int tls13_cookie_verify(const SM4_KEY *cookie_key, // server_ctx->cookie_key
	const uint8_t *client_info, size_t client_info_len,
	const uint8_t *cookie, size_t cookie_len)
{
	return 1;
}

int tls13_cookie_ext_to_bytes(const uint8_t *cookie, size_t cookielen, uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_cookie;
	size_t ext_datalen;

	if (!cookie || !cookielen || cookielen > 65535) {
		error_print();
		return -1;
	}
	ext_datalen = 2 + cookielen;
	if (ext_datalen > 65535) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls_uint16array_to_bytes(cookie, cookielen, out, outlen);
	return 1;
}

int tls13_cookie_from_bytes(const uint8_t **cookie, size_t *cookielen, const uint8_t *ext_data, size_t ext_datalen)
{
	if (tls_uint16array_from_bytes(cookie, cookielen, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (!(*cookie) || !(*cookielen)) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_cookie_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *cookie;
	size_t cookielen;

	if (tls_uint16array_from_bytes(&cookie, &cookielen, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "cookie", cookie, cookielen);
	if (ext_datalen) {
		error_print();
		return -1;
	}
	return 1;
}

// if server send cookie in HelloRetryRequest, client must return cookie in ClientHello2
// so server conn follows cookie setting from ctx, client conn behaves passively
int tls13_ctx_set_cookie_key(TLS_CTX *ctx, const uint8_t *cookie_key, size_t cookie_key_len)
{
	if (!ctx || !cookie_key || !cookie_key_len) {
		error_print();
		return -1;
	}
	if (cookie_key_len != SM4_KEY_SIZE) {
		error_print();
		return -1;
	}

	sm4_set_encrypt_key(&ctx->cookie_key, cookie_key);
	ctx->cookie = 1;

	return 1;
}

