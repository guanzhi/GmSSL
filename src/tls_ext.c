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
#include <fcntl.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/tls.h>


int tls_ext_to_bytes(int ext_type, const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen)
{
	if (!tls_extension_name(ext_type)) {
		error_print();
		return -1;
	}

	if (!outlen) {
		error_print();
		return -1;
	}

	tls_uint16_to_bytes(ext_type, out, outlen);
	tls_uint16array_to_bytes(ext_data, ext_datalen, out, outlen);
	return 1;
}

int tls_ext_from_bytes(int *type, const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen)
{
	uint16_t ext_type;

	if (!type || !data || !datalen || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&ext_type, in, inlen) != 1
		|| tls_uint16array_from_bytes(data, datalen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (!tls_extension_name(ext_type)) {
		warning_print();
	}
	*type = ext_type;
	return 1;
}


/*
11. ec_point_formats

struct {
	ECPointFormat ec_point_format_list<1..2^8-1>
} ECPointFormatList;

Example:
	ext_type: 0x00,0x0B (ec_point_formats)
	ext_length: 0x00,0x02
	ec_point_format_list_len: 0x01
	ec_point_format_list: 0x00 (uncompressed)
*/

int tls_ec_point_formats_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *ec_point_format_list;
	size_t ec_point_format_list_len;
	size_t i;

	format_print(fp, fmt, ind, "ec_point_format_list\n");
	ind += 4;

	if (tls_uint8array_from_bytes(&ec_point_format_list, &ec_point_format_list_len, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < ec_point_format_list_len; i++) {
		format_print(fp, fmt, ind, "%s (%d)\n",
			tls_ec_point_format_name(ec_point_format_list[i]), ec_point_format_list[i]);
	}
	return 1;
}

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

// 似乎不应该保留process函数
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

Example:
	0x00,0x0A, // ext_type = supported_groups
	0x00,0x04, // ext_length
	0x00,0x02, // named_group_list_length
	0x00,0x30, // named_group_list = [ curveSM2 ]

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

int tls_supported_groups_from_bytes(int *groups, size_t *groups_cnt, size_t max_cnt,
	const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *named_group_list;
	size_t named_group_list_len;
	size_t i = 0;

	if (tls_uint16array_from_bytes(&named_group_list, &named_group_list_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (named_group_list_len < 2) {
		error_print();
		return -1;
	}
	while (named_group_list_len) {
		uint16_t group;
		if (tls_uint16_from_bytes(&group, &named_group_list, &named_group_list_len) != 1) {
			error_print();
			return -1;
		}
		if (!tls_named_curve_name(group)) {
			warning_print();
		}
		if (i < max_cnt) {
			groups[i] = group;
			i++;
		}
	}
	*groups_cnt = i;
	return 1;
}

int tls_process_supported_groups(const uint8_t *ext_data, size_t ext_datalen,
	const int *local_groups, size_t local_groups_cnt,
	int *common_groups, size_t *common_groups_cnt, size_t max_cnt)
{
	const uint8_t *named_group_list;
	size_t named_group_list_len;
	const uint8_t *cp;
	size_t len;
	uint16_t group;
	size_t i, j = 0;

	if (tls_uint16array_from_bytes(&named_group_list, &named_group_list_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}

	cp = named_group_list;
	len = named_group_list_len;
	while (len) {
		if (tls_uint16_from_bytes(&group, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (!tls_named_curve_name(group)) {
			warning_print();
			//return -1;
		}
		if (group == local_groups[0] && j < max_cnt) {
			common_groups[j++] = group;
		}
	}

	for (i = 1; i < local_groups_cnt && j < max_cnt; i++) {
		cp = named_group_list;
		len = named_group_list_len;
		while (len) {
			tls_uint16_from_bytes(&group, &cp, &len);
			if (group == local_groups[i]) {
				common_groups[j++] = group;
				break;
			}
		}
	}
	*common_groups_cnt = j;

	if (*common_groups_cnt == 0) {
		return 0;
	}
	return 1;
}

int tls_supported_groups_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	const uint8_t *groups;
	size_t groups_len;

	format_print(fp, fmt, ind, "named_group_list\n");
	ind += 4;

	if (tls_uint16array_from_bytes(&groups, &groups_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	while (groups_len) {
		uint16_t group;
		const char *name;
		if (tls_uint16_from_bytes(&group, &groups, &groups_len) != 1) {
			error_print();
			return -1;
		}
		name = tls_named_curve_name(group);
		if (!name) {
			name = "(unknown)";
		}
		format_print(fp, fmt, ind, "%s (%04x)\n", name, group);
	}
	if (dlen) {
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

Example:
	0x00,0x0D, // ext_type = signature_algors
	0x00,0x04, // ext_length
	0x00,0x02, // supported_signature_algorithms_length
	0x07,0x07, // supported_signature_algorithms = [ sm2sig_sm3 ]


在tls12中，只有ClientHello可以包含这个扩展，ServerHello不允许包含这个扩展
服务器在接收到这个扩展之后，如果
在 TLS 1.2 中，如果服务器收到客户端的 signature_algorithms 扩展，但发现其中没有自己支持的算法
服务器必须中止握手，并返回一个致命的 handshake_failure 警报

*/

int tls_signature_algorithms_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	const uint8_t *sig_algs;
	size_t sig_algs_len;

	if (tls_uint16array_from_bytes(&sig_algs, &sig_algs_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "supported_signature_algorithms\n");
	ind += 4;
	while (sig_algs_len) {
		uint16_t sig_alg;
		if (tls_uint16_from_bytes(&sig_alg, &sig_algs, &sig_algs_len) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "%s (%04x)\n", tls_signature_scheme_name(sig_alg), sig_alg);
	}

	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}


int tls_enable_signature_algorithms_cert(TLS_CONNECT *conn)
{
	if (!conn) {
		error_print();
		return -1;
	}
	if (!conn->ctx->signature_algorithms_cnt) {
		error_print();
		return -1;
	}
	conn->signature_algorithms_cert = 1;
	return 1;
}

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

int tls_process_signature_algorithms(const uint8_t *ext_data, size_t ext_datalen,
	const int *local_sig_algs, size_t local_sig_algs_cnt,
	int *common_sig_algs, size_t *common_sig_algs_cnt, size_t max_cnt)
{
	const uint8_t *supported_sig_algs;
	size_t supported_sig_algs_len;
	const uint8_t *cp;
	size_t len;
	uint16_t sig_alg;
	size_t i, j = 0;

	if (!common_sig_algs || !common_sig_algs_cnt || !max_cnt) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(&supported_sig_algs, &supported_sig_algs_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (supported_sig_algs_len < 2) {
		error_print();
		return -1;
	}

	cp = supported_sig_algs;
	len = supported_sig_algs_len;
	while (len) {
		if (tls_uint16_from_bytes(&sig_alg, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (!tls_signature_scheme_name(sig_alg)) {
			warning_print(); // FIXME
			//return -1;
		}
		if (sig_alg == local_sig_algs[0] && j < max_cnt) {
			common_sig_algs[j++] = sig_alg;
		}
	}

	for (i = 1; i < local_sig_algs_cnt && j < max_cnt; i++) {
		cp = supported_sig_algs;
		len = supported_sig_algs_len;
		while (len) {
			tls_uint16_from_bytes(&sig_alg, &cp, &len);
			if (sig_alg == local_sig_algs[i]) {
				common_sig_algs[j++] = sig_alg;
				break;
			}
		}
	}
	*common_sig_algs_cnt = j;

	if (!(*common_sig_algs_cnt)) {
		warning_print();
		return 0;
	}
	return 1;
}

int tls_signature_algorithms_ext_from_bytes(int *algs, size_t *algs_cnt, size_t max_cnt,
	const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *cp;
	size_t len;
	size_t i;

	if (tls_uint16array_from_bytes(&cp, &len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < max_cnt && len; i++) {
		uint16_t alg;
		if (tls_uint16_from_bytes(&alg, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (!tls_signature_scheme_name(alg)) {
			error_print();
			return -1;
		}
		algs[i] = alg;
	}
	*algs_cnt = i;
	return 1;
}


static int tls_server_parameter_select(const int *server_params, size_t server_params_cnt,
	const int *client_params, size_t client_params_cnt,
	int *selected)
{
	size_t i, j;

	for (i = 0; i < server_params_cnt; i++) {
		*selected = server_params[i];
		for (j = 0; j < client_params_cnt; j++) {
			if (client_params[j] == *selected) {
				return 1;
			}
		}
	}
	error_print();
	return 0;
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
			/*				
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
			*/
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
				
			/*
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
			*/
			*signature_algor = TLS_sig_sm2sig_sm3;
			break;
		default:
			error_print();
			return -1;
		}
	}
	return 1;
}
