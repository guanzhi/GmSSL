/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_TOOLS_TLS_SERVER_HTTP_H
#define GMSSL_TOOLS_TLS_SERVER_HTTP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <gmssl/tls.h>
#include <gmssl/error.h>

static int tls_server_www_append(uint8_t **buf, size_t *len, size_t *cap,
	const uint8_t *data, size_t datalen)
{
	uint8_t *p;
	size_t newlen;
	size_t newcap;

	if (datalen > (size_t)-1 - *len) {
		error_print();
		return -1;
	}
	newlen = *len + datalen;
	if (newlen <= *cap) {
		memcpy(*buf + *len, data, datalen);
		*len = newlen;
		return 1;
	}

	newcap = *cap ? *cap : 4096;
	while (newcap < newlen) {
		if (newcap > ((size_t)-1)/2) {
			newcap = newlen;
			break;
		}
		newcap *= 2;
	}

	if (!(p = realloc(*buf, newcap))) {
		error_print();
		return -1;
	}
	*buf = p;
	*cap = newcap;
	memcpy(*buf + *len, data, datalen);
	*len = newlen;
	return 1;
}

static int tls_server_www_ascii_lower(int c)
{
	if (c >= 'A' && c <= 'Z') {
		return c - 'A' + 'a';
	}
	return c;
}

static int tls_server_www_memcase_equal(const uint8_t *a, const char *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (tls_server_www_ascii_lower(a[i]) != tls_server_www_ascii_lower((unsigned char)b[i])) {
			return 0;
		}
	}
	return 1;
}

static int tls_server_www_starts_with(const uint8_t *buf, size_t len, const char *prefix)
{
	size_t prefix_len = strlen(prefix);

	if (len < prefix_len) {
		return 0;
	}
	return memcmp(buf, prefix, prefix_len) == 0;
}

static int tls_server_www_looks_like_http(const uint8_t *buf, size_t len)
{
	if (tls_server_www_starts_with(buf, len, "GET ")
		|| tls_server_www_starts_with(buf, len, "POST ")
		|| tls_server_www_starts_with(buf, len, "HEAD ")
		|| tls_server_www_starts_with(buf, len, "PUT ")
		|| tls_server_www_starts_with(buf, len, "DELETE ")
		|| tls_server_www_starts_with(buf, len, "PATCH ")
		|| tls_server_www_starts_with(buf, len, "OPTIONS ")
		|| tls_server_www_starts_with(buf, len, "TRACE ")
		|| tls_server_www_starts_with(buf, len, "CONNECT ")) {
		return 1;
	}
	return 0;
}

static int tls_server_www_find_header_end(const uint8_t *buf, size_t len, size_t *header_len)
{
	size_t i;

	for (i = 0; i + 3 < len; i++) {
		if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
			*header_len = i + 4;
			return 1;
		}
	}
	return 0;
}

static int tls_server_www_parse_content_length(const uint8_t *buf, size_t header_len,
	size_t *content_length, int *has_content_length)
{
	const char name[] = "content-length:";
	size_t name_len = sizeof(name) - 1;
	size_t pos = 0;

	*content_length = 0;
	*has_content_length = 0;

	while (pos < header_len) {
		size_t line_end = pos;
		size_t val_pos;
		size_t value = 0;

		while (line_end + 1 < header_len
			&& !(buf[line_end] == '\r' && buf[line_end + 1] == '\n')) {
			line_end++;
		}
		if (line_end > pos + name_len
			&& tls_server_www_memcase_equal(buf + pos, name, name_len)) {
			val_pos = pos + name_len;
			while (val_pos < line_end && (buf[val_pos] == ' ' || buf[val_pos] == '\t')) {
				val_pos++;
			}
			if (val_pos == line_end) {
				return 1;
			}
			while (val_pos < line_end) {
				unsigned int digit;

				if (buf[val_pos] < '0' || buf[val_pos] > '9') {
					return 1;
				}
				digit = buf[val_pos] - '0';
				if (value > ((size_t)-1 - digit)/10) {
					return 1;
				}
				value = value * 10 + digit;
				val_pos++;
			}
			*content_length = value;
			*has_content_length = 1;
			return 1;
		}
		if (line_end + 1 >= header_len) {
			break;
		}
		pos = line_end + 2;
	}

	return 1;
}

static int tls_server_www_request_complete(const uint8_t *buf, size_t len)
{
	size_t header_len;
	size_t content_length;
	int has_content_length;

	if (!tls_server_www_find_header_end(buf, len, &header_len)) {
		if (len && !tls_server_www_looks_like_http(buf, len)) {
			return 1;
		}
		return 0;
	}
	if (tls_server_www_parse_content_length(buf, header_len, &content_length,
		&has_content_length) != 1) {
		return 1;
	}
	if (!has_content_length) {
		return 1;
	}
	if (content_length > (size_t)-1 - header_len) {
		return 1;
	}
	return len >= header_len + content_length;
}

static int tls_server_www_send_all(TLS_CONNECT *conn, const uint8_t *buf, size_t len)
{
	int ret;
	size_t offset = 0;
	fd_set rfds;
	fd_set wfds;

	while (offset < len) {
		size_t sentlen = 0;

		ret = tls_send(conn, buf + offset, len - offset, &sentlen);
		if (ret == 1) {
			offset += sentlen;
			continue;
		}
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		if (ret == TLS_ERROR_RECV_AGAIN) {
			FD_SET(conn->sock, &rfds);
		} else if (ret == TLS_ERROR_SEND_AGAIN) {
			FD_SET(conn->sock, &wfds);
		} else {
			error_print();
			return -1;
		}
		if (select((int)(conn->sock + 1), &rfds, &wfds, NULL, NULL) < 0) {
			error_print();
			return -1;
		}
	}
	return 1;
}

static int tls_server_www_send_response(TLS_CONNECT *conn, const uint8_t *body, size_t bodylen)
{
	char header[256];
	int header_len;

	header_len = snprintf(header, sizeof(header),
		"HTTP/1.0 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n"
		"\r\n", bodylen);
	if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
		error_print();
		return -1;
	}
	if (tls_server_www_send_all(conn, (uint8_t *)header, (size_t)header_len) != 1) {
		return -1;
	}
	if (bodylen && tls_server_www_send_all(conn, body, bodylen) != 1) {
		return -1;
	}
	return 1;
}

#endif
