/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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
#include <fcntl.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/tls.h>


/*
ec_point_formats

  struct {
	ECPointFormat ec_point_format_list<1..2^8-1>
  } ECPointFormatList;
*/
int tls_ec_point_formats_ext_to_bytes(const int *formats, size_t formats_cnt,
	uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_ec_point_formats;
	size_t ext_datalen;
	size_t ec_point_format_list_len;
	size_t i;

	if (!formats || !formats_cnt || !outlen) {
		error_print();
		return -1;
	}
	ec_point_format_list_len = tls_uint8_size() * formats_cnt;
	if (ec_point_format_list_len < 1 || ec_point_format_list_len > 255) {
		error_print();
		return -1;
	}
	ext_datalen = tls_uint8_size() + ec_point_format_list_len;

	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls_uint8_to_bytes((uint8_t)ec_point_format_list_len, out, outlen);
	for (i = 0; i < formats_cnt; i++) {
		if (!tls_ec_point_format_name(formats[i])) {
			error_print();
			return -1;
		}
		tls_uint8_to_bytes((uint8_t)formats[i], out, outlen);
	}
	return 1;
}

int tls_process_client_ec_point_formats(const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen)
{
	int shared_formats[] = { TLS_point_uncompressed };
	size_t shared_formats_cnt = 0;
	const uint8_t *p;
	size_t len;

	if (tls_uint8array_from_bytes(&p, &len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
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
	if (!shared_formats_cnt) {
		error_print();
		return -1;
	}
	if (tls_ec_point_formats_ext_to_bytes(shared_formats, shared_formats_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_process_server_ec_point_formats(const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *p;
	size_t len;
	uint8_t format;

	if (tls_uint8array_from_bytes(&p, &len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
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

#define TLS_MAX_SUPPORTED_GROUPS_COUNT 64


/*
supported_groups

  struct {
	NamedGroup named_group_list<2..2^16-1>;
  } NamedGroupList;
*/
int tls_supported_groups_ext_to_bytes(const int *groups, size_t groups_cnt,
	uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_supported_groups;
	size_t ext_datalen;
	size_t named_group_list_len;
	size_t i;

	if (!groups || !groups_cnt) {
		error_print();
		return -1;
	}
	if (!outlen) {
		error_print();
		return -1;
	}

	if (groups_cnt > ((1<<16) - 1)/2) {
		error_print();
		return -1;
	}
	named_group_list_len = tls_uint16_size() * groups_cnt;
	ext_datalen = tls_uint16_size() + named_group_list_len;

	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls_uint16_to_bytes((uint16_t)named_group_list_len, out, outlen);
	for (i = 0; i < groups_cnt; i++) {
		if (!tls_named_curve_name(groups[i])) {
			error_print();
			return -1;
		}
		tls_uint16_to_bytes((uint16_t)groups[i], out, outlen);
	}
	return 1;
}

int tls_process_client_supported_groups(const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen)
{
	int shared_groups[] = { TLS_curve_sm2p256v1 };
	size_t shared_groups_cnt = 0;
	const uint8_t *p;
	size_t len;

	if (tls_uint16array_from_bytes(&p, &len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	while (len) {
		uint16_t group;
		if (tls_uint16_from_bytes(&group, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (!tls_named_curve_name(group)) {
			error_print();
			return -1;
		}
		if (group == shared_groups[0]) {
			shared_groups_cnt = 1;
		}
	}
	if (!shared_groups_cnt) {
		error_print();
		return -1;
	}
	if (tls_supported_groups_ext_to_bytes(shared_groups, shared_groups_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_process_server_supported_groups(const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *p;
	size_t len;
	uint16_t group;

	if (tls_uint16array_from_bytes(&p, &len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&group, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (group != TLS_curve_sm2p256v1) {
		error_print();
		return -1;
	}
	return 1;
}



#define TLS_MAX_SIGNATURE_ALGORS_COUNT 64

/*
signature_algorithms
signature_algorithms_cert

  struct {
	SignatureScheme supported_signature_algorithms<2..2^16-2>;
  } SignatureSchemeList;
*/
int tls_signature_algorithms_ext_to_bytes_ex(int ext_type, const int *algs, size_t algs_cnt,
	uint8_t **out, size_t *outlen)
{
	size_t ext_datalen;
	size_t supported_signature_algorithms_len;
	size_t i;

	if (!algs || !algs_cnt || !outlen) {
		error_print();
		return -1;
	}
	if (algs_cnt > ((1<<16) - 2)/2) {
		error_print();
		return -1;
	}
	supported_signature_algorithms_len = tls_uint16_size() * algs_cnt;
	ext_datalen = tls_uint16_size() + supported_signature_algorithms_len;

	tls_uint16_to_bytes((uint16_t)ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls_uint16_to_bytes((uint16_t)supported_signature_algorithms_len, out, outlen);
	for (i = 0; i < algs_cnt; i++) {
		if (!tls_signature_scheme_name(algs[i])) {
			error_print();
			return -1;
		}
		tls_uint16_to_bytes((uint16_t)algs[i], out, outlen);
	}
	return 1;
}

int tls_signature_algorithms_ext_to_bytes(const int *algs, size_t algs_cnt,
	uint8_t **out, size_t *outlen)
{
	int ext_type = TLS_extension_signature_algorithms;
	if (tls_signature_algorithms_ext_to_bytes_ex(ext_type, algs, algs_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_signature_algorithms_cert_ext_to_bytes(const int *algs, size_t algs_cnt,
	uint8_t **out, size_t *outlen)
{
	int ext_type = TLS_extension_signature_algorithms_cert;
	if (tls_signature_algorithms_ext_to_bytes_ex(ext_type, algs, algs_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_process_client_signature_algorithms(const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen)
{
	int shared_algs[1] = { TLS_sig_sm2sig_sm3 };
	size_t shared_algs_cnt = 0;
	const uint8_t *p;
	size_t len;

	if (!ext_data || !ext_datalen || !outlen) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(&p, &len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	while (len) {
		uint16_t alg;
		if (tls_uint16_from_bytes(&alg, &p, &len) != 1) {
			error_print();
			return -1;
		}
		/*
		// GmSSL不识别所有的算法！
		if (!tls_signature_scheme_name(alg)) {
			error_print();
			return -1;
		}
		*/
		if (alg == shared_algs[0]) {
			shared_algs_cnt = 1;
			break;
		}
	}
	if (!shared_algs_cnt) {
		error_print();
		return -1;
	}
	if (tls_signature_algorithms_ext_to_bytes(shared_algs, shared_algs_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_process_server_signature_algors(const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *p;
	size_t len;
	uint16_t alg;

	if (tls_uint16array_from_bytes(&p, &len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
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

/*
supported_versions

  struct {
	select (Handshake.msg_type) {
		case client_hello:
			ProtocolVersion versions<2..254>;
		case server_hello: -- and HelloRetryRequest
			ProtocolVersion selected_version;
	};
  } SupportedVersions;
*/

int tls13_supported_versions_ext_print(FILE *fp, int fmt, int ind,
	int handshake_type, const uint8_t *data, size_t datalen)
{
	const uint8_t *versions;
	size_t versions_len;
	uint16_t version;

	switch (handshake_type) {
	case TLS_handshake_client_hello:
		format_print(fp, fmt, ind, "versions\n");
		ind += 4;

		if (tls_uint8array_from_bytes(&versions, &versions_len, &data, &datalen) != 1) {
			error_print();
			return -1;
		}
		if (versions_len < 2 || versions_len > 254) {
			error_print();
			return -1;
		}
		while (versions_len) {
			if (tls_uint16_from_bytes(&version, &versions, &versions_len) != 1) {
				error_print();
				return -1;
			}
			format_print(fp, fmt, ind, "%s (0x%04x)\n", tls_protocol_name(version), version);
		}
		break;

	case TLS_handshake_server_hello:
	case TLS_handshake_hello_retry_request:
		if (tls_uint16_from_bytes(&version, &data, &datalen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "selected_version: %s (0x%04x)\n", tls_protocol_name(version), version);
		break;

	default:
		error_print();
		return -1;
	}

	if (datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_supported_versions_ext_to_bytes(int handshake_type, const int *protos, size_t protos_cnt,
	uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_supported_versions;
	size_t ext_datalen;
	size_t i;

	if (!protos || !protos_cnt || !outlen) {
		error_print();
		return -1;
	}
	switch (handshake_type) {
	case TLS_handshake_client_hello:
		{
		size_t versions_len;
		if (protos_cnt > 254/2) {
			error_print();
			return -1;
		}
 		versions_len = tls_uint16_size() * protos_cnt;
		ext_datalen = tls_uint8_size() + versions_len;
		tls_uint16_to_bytes(ext_type, out, outlen);
		tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
		tls_uint8_to_bytes((uint8_t)versions_len, out, outlen);
		for (i = 0; i < protos_cnt; i++) {
			if (!tls_protocol_name(protos[i])) {
				error_print();
				return -1;
			}
			tls_uint16_to_bytes((uint16_t)protos[i], out, outlen);
		}
		break;
		}
	case TLS_handshake_server_hello:
	case TLS_handshake_hello_retry_request:
		{
		uint16_t selected_version;
		if (protos_cnt > 1) {
			error_print();
			return -1;
		}
		selected_version = protos[0];
		ext_datalen = tls_uint16_size();
		tls_uint16_to_bytes(ext_type, out, outlen);
		tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
		tls_uint16_to_bytes(selected_version, out, outlen);
		break;
		}
	default:
		error_print();
		return -1;
	}
	return 1;
}

int tls13_process_client_supported_versions(const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen)
{
	const uint8_t *versions;
	size_t versions_len;
	int selected_version = -1;

	if (tls_uint8array_from_bytes(&versions, &versions_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (versions_len < 2 || versions_len > 254) {
		error_print();
		return -1;
	}
	while (versions_len) {
		uint16_t proto;
		if (tls_uint16_from_bytes(&proto, &versions, &versions_len) != 1) {
			error_print();
			return -1;
		}
		if (!tls_protocol_name(proto)) {
			error_print();
			return -1;
		}
		if (proto == TLS_protocol_tls13) {
			selected_version = proto;
		}
	}
	if (selected_version < 0) {
		error_print();
		return -1;
	}
	if (tls13_supported_versions_ext_to_bytes(TLS_handshake_server_hello, &selected_version, 1, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_process_server_supported_versions(const uint8_t *ext_data, size_t ext_datalen)
{
	uint16_t selected_version;

	if (tls_uint16_from_bytes(&selected_version, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (selected_version != TLS_protocol_tls13) {
		error_print();
		return -1;
	}
	return 1;
}

/*
key_share

实际上这个 key_share 也存在相同的问题


  struct {
	NamedGroup group;
	opaque key_exchange<1..2^16-1>;
  } KeyShareEntry;

  struct {
	KeyShareEntry client_shares<0..2^16-1>;
  } KeyShareClientHello;

  struct {
	KeyShareEntry server_share;
  } KeyShareServerHello;
*/

int tls13_key_share_ext_print(FILE *fp, int fmt, int ind, int handshake_type, const uint8_t *data, size_t datalen)
{
	const uint8_t *client_shares;
	size_t client_shares_len;
	uint16_t group;
	const uint8_t *key_exchange;
	size_t key_exchange_len;

	switch (handshake_type) {
	case TLS_handshake_client_hello:
		format_print(fp, fmt, ind, "client_shares\n");
		ind += 4;
		if (tls_uint16array_from_bytes(&client_shares, &client_shares_len, &data, &datalen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "KeyShareEntry\n");
		ind += 4;
		while (client_shares_len) {
			if (tls_uint16_from_bytes(&group, &client_shares, &client_shares_len) != 1) goto err;
			format_print(fp, fmt, ind, "group: %s (0x%04x)\n", tls_named_curve_name(group), group);
			if (tls_uint16array_from_bytes(&key_exchange, &key_exchange_len, &client_shares, &client_shares_len) != 1) goto err;
			format_bytes(fp, fmt, ind, "key_exchange", key_exchange, key_exchange_len);
		}
		break;
	case TLS_handshake_server_hello:
		format_print(fp, fmt, ind, "server_share\n");
		ind += 4;
		if (tls_uint16_from_bytes(&group, &data, &datalen) != 1) goto err;
		format_print(fp, fmt, ind, "group: %s (0x%04x)\n", tls_named_curve_name(group), group);
		if (tls_uint16array_from_bytes(&key_exchange, &key_exchange_len, &data, &datalen) != 1) goto err;
		format_bytes(fp, fmt, ind, "key_exchange", key_exchange, key_exchange_len);
		break;
	default:
		error_print();
		return -1;
	}
	if (tls_length_is_zero(datalen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int tls13_key_share_entry_to_bytes(const SM2_POINT *point, uint8_t **out, size_t *outlen)
{
	uint16_t group = TLS_curve_sm2p256v1;
	uint8_t key_exchange[65];

	if (!point || !outlen) {
		error_print();
		return -1;
	}
	sm2_point_to_uncompressed_octets(point, key_exchange);
	tls_uint16_to_bytes(group, out, outlen);
	tls_uint16array_to_bytes(key_exchange, 65, out, outlen);
	return 1;
}

int tls13_server_key_share_ext_to_bytes(const SM2_POINT *point, uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_key_share;
	size_t ext_datalen = 0;

	if (!point || !outlen) {
		error_print();
		return -1;
	}
	tls13_key_share_entry_to_bytes(point, NULL, &ext_datalen);
	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls13_key_share_entry_to_bytes(point, out, outlen);
	return 1;
}

int tls13_process_server_key_share(const uint8_t *ext_data, size_t ext_datalen, SM2_POINT *point)
{
	uint16_t group;
	const uint8_t *key_exchange;
	size_t key_exchange_len;

	if (!point) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&group, &ext_data, &ext_datalen) != 1
		|| tls_uint16array_from_bytes(&key_exchange, &key_exchange_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (group != TLS_curve_sm2p256v1) {
		error_print();
		return -1;
	}
	if (key_exchange_len != 65) {
		error_print();
		return -1;
	}
	if (sm2_point_from_octets(point, key_exchange, key_exchange_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_client_key_share_ext_to_bytes(const SM2_POINT *point, uint8_t **out, size_t *outlen)
{
	uint16_t ext_type = TLS_extension_key_share;
	size_t ext_datalen;
	size_t client_shares_len = 0;

	if (!point || !outlen) {
		error_print();
		return -1;
	}
	tls13_key_share_entry_to_bytes(point, NULL, &client_shares_len);
	ext_datalen = tls_uint16_size() + client_shares_len;

	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen); // FIXME: do we need to check length < UINT16_MAX?
	tls_uint16_to_bytes((uint16_t)client_shares_len, out, outlen);
	tls13_key_share_entry_to_bytes(point, out, outlen);
	return 1;
}

int tls13_process_client_key_share(const uint8_t *ext_data, size_t ext_datalen,
	const SM2_KEY *server_ecdhe_key, SM2_POINT *client_ecdhe_public,
	uint8_t **out, size_t *outlen)
{
	const uint8_t *client_shares;
	size_t client_shares_len;
	uint16_t group;
	const uint8_t *key_exchange;
	size_t key_exchange_len;

	if (!server_ecdhe_key || !client_ecdhe_public || !outlen) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(&client_shares, &client_shares_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	while (client_shares_len) {
		if (tls_uint16_from_bytes(&group, &client_shares, &client_shares_len) != 1
			|| tls_uint16array_from_bytes(&key_exchange, &key_exchange_len, &client_shares, &client_shares_len) != 1) {
			error_print();
			return -1;
		}
		if (!tls_named_curve_name(group)) {
			error_print();
			return -1;
		}
		if (!key_exchange) {
			error_print();
			return -1;
		}
		if (group == TLS_curve_sm2p256v1) {
			if (key_exchange_len != 65) {
				error_print();
				return -1;
			}
			if (sm2_point_from_octets(client_ecdhe_public, key_exchange, key_exchange_len) != 1) {
				error_print();
				return -1;
			}
			if (tls13_server_key_share_ext_to_bytes(&server_ecdhe_key->public_key, out, outlen) != 1) {
				error_print();
				return -1;
			}
			return 1;
		}
	}
	error_print();
	return -1;
}

/*
certificate_authorities

  opaque DistinguishedName<1..2^16-1>;

  struct {
	DistinguishedName authorities<3..2^16-1>;
  } CertificateAuthoritiesExtension;
*/

int tls13_certificate_authorities_ext_to_bytes(const uint8_t *ca_names, size_t ca_names_len,
	uint8_t **out, size_t *outlen)
{
	int ext_type = TLS_extension_certificate_authorities;
	size_t ext_datalen;
	size_t authorities_len;
	const uint8_t *name;
	size_t namelen;
	const uint8_t *p;
	size_t len;

	p = ca_names;
	len = ca_names_len;
	authorities_len = 0;
	while (len) {
		if (x509_name_from_der(&name, &namelen, &p, &len) != 1) {
			error_print();
			return -1;
		}
		tls_uint16array_to_bytes(name, namelen, NULL, &authorities_len);
	}
	if (authorities_len < 3 || authorities_len > (1 << 16) - 1) {
		error_print();
		return -1;
	}
	ext_datalen = tls_uint16_size() + authorities_len;

	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16_to_bytes((uint16_t)ext_datalen, out, outlen);
	tls_uint16_to_bytes((uint16_t)authorities_len, out, outlen);
	while (ca_names_len) {
		x509_name_from_der(&name, &namelen, &ca_names, &ca_names_len);
		tls_uint16array_to_bytes(name, namelen, out, outlen);
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

int tls_process_client_hello_exts(const uint8_t *exts, size_t extslen, uint8_t *out, size_t *outlen, size_t maxlen)
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
			if (tls_process_client_ec_point_formats(data, datalen, &out, outlen) != 1) {
				error_print();
				return -1;
			}
			break;
		case TLS_extension_signature_algorithms:
			if (tls_process_client_signature_algorithms(data, datalen, &out, outlen) != 1) {
				error_print();
				return -1;
			}
			break;
		case TLS_extension_supported_groups:
			if (tls_process_client_supported_groups(data, datalen, &out, outlen) != 1) {
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

int tls_process_server_hello_exts(const uint8_t *exts, size_t extslen,
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



static int tls13_server_hello_exts[] = {
	TLS_extension_key_share,
	TLS_extension_pre_shared_key,
	TLS_extension_supported_versions,
};

/*
struct {
	Extension extensions<0..2^16-1>;
} EncryptedExtensions;
*/
static int tls13_encrypted_extensions_exts[] = {
	TLS_extension_server_name,
	TLS_extension_max_fragment_length,
	TLS_extension_supported_groups, // 必须放在EE中，不能放在SH中
	TLS_extension_use_srtp,
	TLS_extension_heartbeat,
	TLS_extension_application_layer_protocol_negotiation,
	TLS_extension_client_certificate_type,
	TLS_extension_server_certificate_type,
	TLS_extension_early_data,
};

static int tls13_certificate_exts[] = {
	TLS_extension_status_request,
	TLS_extension_signed_certificate_timestamp,
};

static int tls13_certificate_request_exts[] = {
	TLS_extension_status_request,
	TLS_extension_signature_algorithms,
	TLS_extension_signed_certificate_timestamp,
	TLS_extension_certificate_authorities,
	TLS_extension_oid_filters,
	TLS_extension_signature_algorithms_cert,
};

static int tls13_hello_retry_request_exts[] = {
	TLS_extension_key_share,
	TLS_extension_cookie,
	TLS_extension_supported_versions,
};






























