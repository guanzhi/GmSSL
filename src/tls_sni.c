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

#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>

/*
server_name (SNI)

ClientHello.server_name
	ext_data = ServerName server_name_list<1..2^16-1>
	struct {
		uint8 name_type = host_name(0);
		opaque host_name<1..2^16-1>;
	} ServerName;

ServerHello.server_name
	ext_data = empty
*/

int tls_server_name_ext_to_bytes(const uint8_t *host_name, size_t host_name_len, uint8_t **out, size_t *outlen)
{
	int type = TLS_extension_server_name;
	uint8_t *ext_data = NULL;
	size_t ext_datalen = 0;
	uint8_t *server_name_list = NULL;
	size_t server_name_list_len = 0;

	if (out && *out) {
		ext_data = *out + 4; // sizeof(ext_header) == 4
		server_name_list = ext_data + 2; // sizeof(host_name_list_len) == 2
	}

	// output one host_name to server_name_list
	tls_uint8_to_bytes(TLS_name_type_host_name, &server_name_list, &server_name_list_len);
	tls_uint16array_to_bytes(host_name, host_name_len, &server_name_list, &server_name_list_len);
	// output ext data
	tls_uint16array_to_bytes(NULL, server_name_list_len, &ext_data, &ext_datalen);
	// output ext header
	tls_ext_to_bytes(type, NULL, ext_datalen, out, outlen);

	return 1;
}

int tls_server_name_from_bytes(const uint8_t **host_name, size_t *host_name_len,
	const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *server_name_list;
	size_t server_name_list_len;

	if (!host_name || !host_name_len) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(&server_name_list, &server_name_list_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (!server_name_list) {
		error_print();
		return -1;
	}
	while (server_name_list_len) {
		uint8_t name_type;
		const uint8_t *name;
		size_t namelen;

		if (tls_uint8_from_bytes(&name_type, &server_name_list, &server_name_list_len) != 1
			|| tls_uint16array_from_bytes(&name, &namelen, &server_name_list, &server_name_list_len) != 1) {
			error_print();
			return -1;
		}
		if (name_type != TLS_name_type_host_name) {
			error_print();
			return -1;
		}
		if (!name) {
			error_print();
			return -1;
		}
		// only return the first hostname
		if (*host_name == NULL) {
			*host_name = name;
			*host_name_len = namelen;
		}
	}
	return 1;
}

int tls_server_name_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *server_name_list;
	size_t server_name_list_len;
	uint8_t name_type;
	const uint8_t *host_name;
	size_t host_name_len;

	if (tls_uint16array_from_bytes(&server_name_list, &server_name_list_len, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	while (server_name_list_len) {
		if (tls_uint8_from_bytes(&name_type, &server_name_list, &server_name_list_len) != 1
			|| tls_uint16array_from_bytes(&host_name, &host_name_len, &server_name_list, &server_name_list_len) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "name_type: %s (%d)\n", name_type == 0 ? "host_name" : "(unknown)", name_type);
		format_string(fp, fmt, ind, "host_name", host_name, host_name_len); // TODO: print string
	}
	if (ext_datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_set_server_name(TLS_CONNECT *conn, const uint8_t *host_name, size_t host_name_len)
{
	if (!conn || !host_name || !host_name_len) {
		error_print();
		return -1;
	}
	if (!conn->is_client) {
		error_print();
		return -1;
	}
	if (host_name_len >= sizeof(conn->host_name)) {
		error_print();
		return -1;
	}
	memcpy(conn->host_name, host_name, host_name_len);
	conn->host_name[host_name_len] = 0;
	conn->host_name_len = host_name_len;
	conn->server_name = 1;
	return 1;
}


