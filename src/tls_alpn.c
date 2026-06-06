/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/error.h>
#include <gmssl/tls.h>


#define tls_application_layer_protocol_negotiation_max_count() \
	(sizeof(((TLS_CTX *)0)->alpn_protocols) \
		/ sizeof(((TLS_CTX *)0)->alpn_protocols[0]))


/*
16. application_layer_protocol_negotiation

opaque ProtocolName<1..2^8-1>;

struct {
	ProtocolName protocol_name_list<2..2^16-1>
} ProtocolNameList;

ClientHello.application_layer_protocol_negotiation
	ext_data = ProtocolNameList
	protocol_name_list contains one or more ProtocolName values

EncryptedExtensions.application_layer_protocol_negotiation
	ext_data = ProtocolNameList
	protocol_name_list contains exactly one selected ProtocolName

GmSSL keeps ALPN protocols as caller-owned char * strings. The selected
protocol returned by these helpers points to a local protocol string, not to
the peer's extension buffer.
*/

static int tls_application_layer_protocol_negotiation_check(
	const char *protocol)
{
	size_t len;

	if (!protocol) {
		error_print();
		return -1;
	}
	len = strlen(protocol);
	if (len < 1 || len > 255) {
		error_print();
		return -1;
	}
	return 1;
}

static int tls_application_layer_protocol_negotiation_match(
	const uint8_t *peer_protocol, size_t peer_protocol_len,
	const char *local_protocol)
{
	size_t local_protocol_len;

	if (!peer_protocol || !peer_protocol_len || !local_protocol) {
		return 0;
	}
	local_protocol_len = strlen(local_protocol);
	if (peer_protocol_len != local_protocol_len) {
		return 0;
	}
	if (memcmp(peer_protocol, local_protocol, peer_protocol_len) != 0) {
		return 0;
	}
	return 1;
}

int tls_application_layer_protocol_negotiation_ext_to_bytes(
	char *protocols[], size_t protocols_cnt,
	uint8_t **out, size_t *outlen)
{
	size_t protocol_name_list_len = 0;
	size_t ext_datalen;
	size_t i;

	if (!protocols || !protocols_cnt
		|| protocols_cnt > tls_application_layer_protocol_negotiation_max_count()
		|| !outlen) {
		error_print();
		return -1;
	}
	for (i = 0; i < protocols_cnt; i++) {
		size_t len;

		if (tls_application_layer_protocol_negotiation_check(protocols[i]) != 1) {
			error_print();
			return -1;
		}
		len = strlen(protocols[i]);
		protocol_name_list_len += tls_uint8_size() + len;
	}
	if (protocol_name_list_len < 2 || protocol_name_list_len > 65535) {
		error_print();
		return -1;
	}
	ext_datalen = tls_uint16_size() + protocol_name_list_len;

	tls_uint16_to_bytes(TLS_extension_application_layer_protocol_negotiation, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls_uint16_to_bytes((uint16_t)protocol_name_list_len, out, outlen);
	for (i = 0; i < protocols_cnt; i++) {
		size_t len = strlen(protocols[i]);
		tls_uint8_to_bytes((uint8_t)len, out, outlen);
		if (out && *out) {
			memcpy(*out, protocols[i], len);
			*out += len;
		}
		*outlen += len;
	}

	return 1;
}

int tls_application_layer_protocol_negotiation_selected_ext_to_bytes(
	char *protocol, uint8_t **out, size_t *outlen)
{
	return tls_application_layer_protocol_negotiation_ext_to_bytes(&protocol, 1, out, outlen);
}

int tls_application_layer_protocol_negotiation_from_bytes(
	const uint8_t **protocol_name_list, size_t *protocol_name_list_len,
	const uint8_t *ext_data, size_t ext_datalen)
{
	if (!protocol_name_list || !protocol_name_list_len) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(protocol_name_list, protocol_name_list_len,
			&ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (!*protocol_name_list || *protocol_name_list_len < 2) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_application_layer_protocol_negotiation_select(
	const uint8_t *ext_data, size_t ext_datalen,
	char *local_protocols[], size_t local_protocols_cnt, char **selected)
{
	const uint8_t *protocol_name_list;
	size_t protocol_name_list_len;
	size_t i;

	if (!local_protocols || !local_protocols_cnt
		|| local_protocols_cnt > tls_application_layer_protocol_negotiation_max_count()
		|| !selected) {
		error_print();
		return -1;
	}
	*selected = NULL;

	for (i = 0; i < local_protocols_cnt; i++) {
		if (tls_application_layer_protocol_negotiation_check(local_protocols[i]) != 1) {
			error_print();
			return -1;
		}
	}
	if (tls_application_layer_protocol_negotiation_from_bytes(
			&protocol_name_list, &protocol_name_list_len,
			ext_data, ext_datalen) != 1) {
		error_print();
		return -1;
	}

	while (protocol_name_list_len) {
		const uint8_t *peer_protocol;
		size_t peer_protocol_len;

		if (tls_uint8array_from_bytes(&peer_protocol, &peer_protocol_len,
				&protocol_name_list, &protocol_name_list_len) != 1) {
			error_print();
			return -1;
		}
		if (!peer_protocol || !peer_protocol_len) {
			error_print();
			return -1;
		}

		for (i = 0; i < local_protocols_cnt; i++) {
			if (tls_application_layer_protocol_negotiation_match(
					peer_protocol, peer_protocol_len,
					local_protocols[i]) == 1) {
				*selected = local_protocols[i];
				return 1;
			}
		}
	}

	return 0;
}

int tls_application_layer_protocol_negotiation_selected_from_bytes(
	char **selected, const uint8_t *ext_data, size_t ext_datalen,
	char *local_protocols[], size_t local_protocols_cnt)
{
	const uint8_t *protocol_name_list;
	size_t protocol_name_list_len;
	const uint8_t *peer_protocol;
	size_t peer_protocol_len;
	size_t i;

	if (!selected || !local_protocols || !local_protocols_cnt
		|| local_protocols_cnt > tls_application_layer_protocol_negotiation_max_count()) {
		error_print();
		return -1;
	}
	*selected = NULL;

	for (i = 0; i < local_protocols_cnt; i++) {
		if (tls_application_layer_protocol_negotiation_check(local_protocols[i]) != 1) {
			error_print();
			return -1;
		}
	}
	if (tls_application_layer_protocol_negotiation_from_bytes(
			&protocol_name_list, &protocol_name_list_len,
			ext_data, ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(&peer_protocol, &peer_protocol_len,
			&protocol_name_list, &protocol_name_list_len) != 1
		|| tls_length_is_zero(protocol_name_list_len) != 1) {
		error_print();
		return -1;
	}
	if (!peer_protocol || !peer_protocol_len) {
		error_print();
		return -1;
	}

	for (i = 0; i < local_protocols_cnt; i++) {
		if (tls_application_layer_protocol_negotiation_match(
				peer_protocol, peer_protocol_len,
				local_protocols[i]) == 1) {
			*selected = local_protocols[i];
			return 1;
		}
	}

	return 0;
}

int tls_application_layer_protocol_negotiation_print(
	FILE *fp, int fmt, int ind,
	const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *protocol_name_list;
	size_t protocol_name_list_len;

	format_print(fp, fmt, ind, "protocol_name_list\n");
	ind += 4;

	if (tls_application_layer_protocol_negotiation_from_bytes(
			&protocol_name_list, &protocol_name_list_len,
			ext_data, ext_datalen) != 1) {
		error_print();
		return -1;
	}
	while (protocol_name_list_len) {
		const uint8_t *protocol;
		size_t protocol_len;

		if (tls_uint8array_from_bytes(&protocol, &protocol_len,
				&protocol_name_list, &protocol_name_list_len) != 1) {
			error_print();
			return -1;
		}
		if (!protocol || !protocol_len) {
			error_print();
			return -1;
		}
		format_string(fp, fmt, ind, "ProtocolName", protocol, protocol_len);
	}

	return 1;
}
