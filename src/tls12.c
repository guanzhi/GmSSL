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
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/mem.h>
#include <gmssl/tls.h>


const int tls12_supported_groups[] = {
	TLS_curve_sm2p256v1,
#ifdef ENABLE_SECP256R1
	TLS_curve_secp256r1,
#endif
};
const size_t tls12_supported_groups_cnt =
	sizeof(tls12_supported_groups)/sizeof(tls12_supported_groups[0]);

const int tls12_signature_algorithms[] = {
	TLS_sig_sm2sig_sm3,
#if defined(ENABLE_SECP256R1) && defined(ENABLE_SHA2)
	TLS_sig_ecdsa_secp256r1_sha256,
#endif
};
const size_t tls12_signature_algorithms_cnt =
	sizeof(tls12_signature_algorithms)/sizeof(tls12_signature_algorithms[0]);

const int tls12_cipher_suites[] = {
	TLS_cipher_ecdhe_sm4_cbc_sm3,
	TLS_cipher_ecdhe_sm4_gcm_sm3,
#if defined(ENABLE_AES) && defined(ENABLE_SHA2) && defined(ENABLE_SECP256R1)
	TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256,
	TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256,
#ifdef ENABLE_AES_CCM
	TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm_sha256,
#endif
#endif
};
const size_t tls12_cipher_suites_cnt =
	sizeof(tls12_cipher_suites)/sizeof(tls12_cipher_suites[0]);


int tls_named_curve_oid(int named_curve)
{
	switch (named_curve) {
	case TLS_curve_secp256r1: return OID_secp256r1;
	case TLS_curve_sm2p256v1: return OID_sm2;
	}
	return OID_undef;
}

int tls_named_curve_from_oid(int oid)
{
	switch (oid) {
	case OID_secp256r1: return TLS_curve_secp256r1;
	case OID_sm2: return TLS_curve_sm2p256v1;
	}
	return 0;
}


int tls12_record_set_handshake_client_key_exchange(uint8_t *record, size_t *recordlen,
	const uint8_t *point_octets, size_t point_octets_len)
{
	int type = TLS_handshake_client_key_exchange;
	uint8_t *p = tls_handshake_data(tls_record_data(record));
	size_t len = 0;

	if (point_octets_len != 65) {
		error_print();
		return -1;
	}
	tls_uint8array_to_bytes(point_octets, (uint8_t)point_octets_len, &p, &len);

	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls12_record_get_handshake_client_key_exchange(const uint8_t *record,
	const uint8_t **point_octets, size_t *point_octets_len)
{
	int type;
	const uint8_t *p;
	size_t len;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_client_key_exchange) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(point_octets, point_octets_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (*point_octets_len != 65) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

/*
struct {
	ClientCertificateType certificate_types<1..2^8-1>;
	SignatureAndHashAlgorithm supported_signature_algorithms<2^16-1>; // TLS 1.2 only
	DistinguishedName certificate_authorities<0..2^16-1>;
} CertificateRequest;
*/
int tls12_record_set_handshake_certificate_request(uint8_t *record, size_t *recordlen,
	const uint8_t *cert_types, size_t cert_types_len,
	const uint8_t *sig_algs, size_t sig_algs_len,
	const uint8_t *ca_names, size_t ca_names_len)
{
	int type = TLS_handshake_certificate_request;
	uint8_t *p;
	size_t len =0;
	size_t datalen = 0;

	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	if (cert_types) {
		if (cert_types_len == 0 || cert_types_len > TLS_MAX_CERTIFICATE_TYPES) {
			error_print();
			return -1;
		}
	}
	if (ca_names) {
		if (ca_names_len == 0 || ca_names_len > TLS_MAX_CA_NAMES_SIZE) {
			error_print();
			return -1;
		}
	}
	tls_uint8array_to_bytes(cert_types, cert_types_len, NULL, &datalen);
	tls_uint16array_to_bytes(ca_names, ca_names_len, NULL, &datalen);
	if (datalen > TLS_MAX_HANDSHAKE_DATA_SIZE) {
		error_print();
		return -1;
	}
	p = tls_handshake_data(tls_record_data(record));
	tls_uint8array_to_bytes(cert_types, cert_types_len, &p, &len);
	tls_uint16array_to_bytes(ca_names, ca_names_len, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, datalen);
	return 1;
}

int tls12_record_get_handshake_certificate_request(const uint8_t *record,
	const uint8_t **cert_types, size_t *cert_types_len,
	const uint8_t **sig_algs, size_t *sig_algs_len,
	const uint8_t **ca_names, size_t *ca_names_len)
{
	int type;
	const uint8_t *cp;
	size_t len;
	size_t i;

	if (!record || !cert_types || !cert_types_len || !ca_names || !ca_names_len) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate_request) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(cert_types, cert_types_len, &cp, &len) != 1
		|| tls_uint16array_from_bytes(ca_names, ca_names_len, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	if (*cert_types == NULL) {
		error_print();
		return -1;
	}
	for (i = 0; i < *cert_types_len; i++) {
		if (!tls_cert_type_name((*cert_types)[i])) {
			error_print();
			return -1;
		}
	}
	if (*ca_names) {
		const uint8_t *names = *ca_names;
		size_t nameslen = *ca_names_len;
		while (nameslen) {
			if (tls_uint16array_from_bytes(&cp, &len, &names, &nameslen) != 1) {
				error_print();
				return -1;
			}
		}
	}
	return 1;
}

void tls_clean_record(TLS_CONNECT *conn)
{
	conn->record_offset = 0;
	conn->recordlen = 0;
}


int tls_handshake_init(TLS_CONNECT *conn)
{

	//sm3_init(&conn->sm3_ctx);
	digest_init(&conn->dgst_ctx, DIGEST_sm3());


	return 1;
}

const int ec_point_formats[] = { TLS_point_uncompressed };
size_t ec_point_formats_cnt = sizeof(ec_point_formats)/sizeof(ec_point_formats[0]);

int tls12_ctx_set_renegotiation_info(TLS_CTX *ctx, int enable)
{
	if (!ctx || ctx->protocol != TLS_protocol_tls12) {
		error_print();
		return -1;
	}
	ctx->renegotiation_info = enable ? 1 : 0;
	return 1;
}

int tls12_ctx_set_empty_renegotiation_info_scsv(TLS_CTX *ctx, int enable)
{
	if (!ctx || ctx->protocol != TLS_protocol_tls12) {
		error_print();
		return -1;
	}
	ctx->empty_renegotiation_info_scsv = enable ? 1 : 0;
	return 1;
}

static int tls12_renegotiation_info_ext_is_empty(const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *renegotiated_connection;
	size_t renegotiated_connection_len;

	if (tls_uint8array_from_bytes(&renegotiated_connection, &renegotiated_connection_len,
		&ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	return renegotiated_connection_len == 0;
}

static int tls12_cipher_suites_include_empty_renegotiation_info_scsv(
	const uint8_t *cipher_suites, size_t cipher_suites_len)
{
	while (cipher_suites_len) {
		uint16_t cipher_suite;

		if (tls_uint16_from_bytes(&cipher_suite, &cipher_suites, &cipher_suites_len) != 1) {
			error_print();
			return -1;
		}
		if (cipher_suite == TLS_cipher_empty_renegotiation_info_scsv) {
			return 1;
		}
	}
	return 0;
}



int tls_send_client_hello(TLS_CONNECT *conn)
{
	int ret;

	if (!conn->recordlen) {
		uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
		uint8_t *pexts = exts;
		size_t extslen = 0;
		int cipher_suites[TLS_MAX_CIPHER_SUITES_COUNT + 1];
		const int *client_cipher_suites = conn->ctx->cipher_suites;
		size_t client_cipher_suites_cnt = conn->ctx->cipher_suites_cnt;

		if(conn->verbose)
			tls_trace("send ClientHello\n");

		tls_record_set_protocol(conn->record, TLS_protocol_tls1);

		if (tls_random_generate(conn->client_random) != 1) {
			error_print();
			return -1;
		}

		// ec_point_formats
		if (tls_ec_point_formats_ext_to_bytes(
			ec_point_formats, ec_point_formats_cnt, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}

		// supported_groups
		if (conn->ctx->supported_groups_cnt) {
			if (tls_supported_groups_ext_to_bytes(conn->ctx->supported_groups,
				conn->ctx->supported_groups_cnt, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// signature_algorithms
		if (conn->ctx->signature_algorithms_cnt) {
			if (tls_signature_algorithms_ext_to_bytes(conn->ctx->signature_algorithms,
				conn->ctx->signature_algorithms_cnt, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// trusted_ca_keys
		if (conn->ctx->trusted_ca_keys) {
			if (tls_trusted_ca_keys_ext_to_bytes(conn->ctx->trusted_authorities,
				conn->ctx->trusted_authorities_len, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// server_name
		if (conn->server_name) {
			if (tls_server_name_ext_to_bytes(conn->host_name, conn->host_name_len, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// renegotiation_info
		if (conn->ctx->renegotiation_info) {
			uint8_t ext_data[1] = { 0 };

			if (conn->ctx->empty_renegotiation_info_scsv) {
				error_print();
				return -1;
			}
			if (tls_ext_to_bytes(TLS_extension_renegotiation_info,
				ext_data, sizeof(ext_data), &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// TLS_EMPTY_RENEGOTIATION_INFO_SCSV
		if (conn->ctx->empty_renegotiation_info_scsv) {
			memcpy(cipher_suites, conn->ctx->cipher_suites,
				conn->ctx->cipher_suites_cnt * sizeof(conn->ctx->cipher_suites[0]));
			cipher_suites[conn->ctx->cipher_suites_cnt] = TLS_cipher_empty_renegotiation_info_scsv;
			client_cipher_suites = cipher_suites;
			client_cipher_suites_cnt = conn->ctx->cipher_suites_cnt + 1;
		}

		if (tls_record_set_handshake_client_hello(conn->record, &conn->recordlen,
			conn->protocol, conn->client_random, NULL, 0,
			client_cipher_suites, client_cipher_suites_cnt,
			exts, extslen) != 1) {
			error_print();
			return -1;
		}

		if (conn->verbose)
			tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

		// backup ClientHello
		memcpy(conn->plain_record, conn->record, conn->recordlen);
		conn->plain_recordlen = conn->recordlen;


		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}
	}

	/*
	if (conn->client_certificate_verify) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}
	*/

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	tls_clean_record(conn);
	return 1;
}

/*
const int server_ciphers[] = { TLS_cipher_ecdhe_sm4_cbc_sm3 };
const size_t server_ciphers_cnt = 1;
*/
const int curve = TLS_curve_sm2p256v1;

static int tls12_cipher_suite_get(int cipher_suite, const BLOCK_CIPHER **cipher, const DIGEST **digest)
{
	switch (cipher_suite) {
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
		*cipher = BLOCK_CIPHER_sm4();
		*digest = DIGEST_sm3();
		break;
#if defined(ENABLE_AES) && defined(ENABLE_SHA2) && defined(ENABLE_SECP256R1)
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
#ifdef ENABLE_AES_CCM
	case TLS_cipher_ecdhe_ecdsa_aes_128_ccm:
#endif
		*cipher = BLOCK_CIPHER_aes128();
		*digest = DIGEST_sha256();
		break;
#endif
	default:
		error_print();
		return -1;
	}
	return 1;
}

static int tls12_cipher_suite_match_cert_group(int cipher_suite, int cert_group)
{
	switch (cipher_suite) {
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
		return cert_group == TLS_curve_sm2p256v1;
#if defined(ENABLE_AES) && defined(ENABLE_SHA2) && defined(ENABLE_SECP256R1)
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
#ifdef ENABLE_AES_CCM
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm:
#endif
		return cert_group == TLS_curve_secp256r1;
#endif
	default:
		return 0;
	}
}

static int tls12_signature_scheme_match_cert_group(int sig_alg, int cert_group)
{
	return tls_signature_scheme_group_oid(sig_alg) == tls_named_curve_oid(cert_group);
}

static int tls12_signature_scheme_match_cipher_suite(int sig_alg, int cipher_suite)
{
	switch (sig_alg) {
	case TLS_sig_sm2sig_sm3:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_sm4_cbc_sm3:
		case TLS_cipher_ecdhe_sm4_gcm_sm3:
			return 1;
		}
		break;
	case TLS_sig_ecdsa_secp256r1_sha256:
#if defined(ENABLE_AES) && defined(ENABLE_SHA2) && defined(ENABLE_SECP256R1)
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
#ifdef ENABLE_AES_CCM
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm:
#endif
			return 1;
		}
#endif
		break;
	}
	return 0;
}

static int tls12_key_exchange_group_match_cipher_suite(int group, int cipher_suite)
{
	switch (cipher_suite) {
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
		return group == TLS_curve_sm2p256v1;
#if defined(ENABLE_AES) && defined(ENABLE_SHA2) && defined(ENABLE_SECP256R1)
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
#ifdef ENABLE_AES_CCM
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm:
#endif
		return group == TLS_curve_secp256r1;
#endif
	default:
		return 0;
	}
}

static int tls12_select_common_cipher_suites(const uint8_t *client_ciphers, size_t client_ciphers_len,
	const int *server_ciphers, size_t server_ciphers_cnt,
	int *common_ciphers, size_t *common_ciphers_cnt, size_t max_cnt)
{
	size_t i;

	if (!client_ciphers || !client_ciphers_len
		|| !server_ciphers || !server_ciphers_cnt
		|| !common_ciphers || !common_ciphers_cnt || !max_cnt) {
		error_print();
		return -1;
	}

	*common_ciphers_cnt = 0;
	for (i = 0; i < server_ciphers_cnt && *common_ciphers_cnt < max_cnt; i++) {
		const uint8_t *p = client_ciphers;
		size_t len = client_ciphers_len;
		while (len) {
			uint16_t cipher;
			if (tls_uint16_from_bytes(&cipher, &p, &len) != 1) {
				error_print();
				return -1;
			}
			if (cipher == server_ciphers[i]) {
				common_ciphers[(*common_ciphers_cnt)++] = server_ciphers[i];
				break;
			}
		}
	}

	return *common_ciphers_cnt ? 1 : 0;
}

// support_uncompressed
static int tls_ec_point_formats_support_uncompressed(const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *formats;
	size_t formats_len;
	int uncompressed = 0;

	if (tls_uint8array_from_bytes(&formats, &formats_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (!formats_len) {
		error_print();
		return -1;
	}

	while (formats_len) {
		uint8_t format;
		if (tls_uint8_from_bytes(&format, &formats, &formats_len) != 1) {
			error_print();
			return -1;
		}
		if (!tls_ec_point_format_name(format)) {
			error_print();
			return -1;
		}
		if (format == TLS_point_uncompressed) {
			uncompressed = 1;
		}
	}

	if (!uncompressed) {
		error_print();
		return 0;
	}
	return 1;
}

static int tls12_cert_chain_get_end_entity_group(const uint8_t *cert_chain, size_t cert_chain_len, int *group)
{
	const uint8_t *cert;
	size_t certlen;
	X509_KEY public_key;

	if (!cert_chain || !cert_chain_len || !group) {
		error_print();
		return -1;
	}
	if (x509_certs_get_cert_by_index(cert_chain, cert_chain_len, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1) {
		error_print();
		return -1;
	}
	if (public_key.algor != OID_ec_public_key) {
		error_print();
		return -1;
	}
	if ((*group = tls_named_curve_from_oid(public_key.algor_param)) == 0) {
		error_print();
		return -1;
	}
	return 1;
}

static int tls12_public_key_get_group(const X509_KEY *public_key, int *group)
{
	if (!public_key || !group) {
		error_print();
		return -1;
	}
	if (public_key->algor != OID_ec_public_key) {
		error_print();
		return -1;
	}
	if ((*group = tls_named_curve_from_oid(public_key->algor_param)) == 0) {
		error_print();
		return -1;
	}
	return 1;
}

static int tls12_select_key_exchange_group(const int *groups, size_t groups_cnt,
	int cipher_suite, int *selected_group)
{
	size_t i;

	if (!groups || !groups_cnt || !selected_group) {
		error_print();
		return -1;
	}
	for (i = 0; i < groups_cnt; i++) {
		if (tls12_key_exchange_group_match_cipher_suite(groups[i], cipher_suite)) {
			*selected_group = groups[i];
			return 1;
		}
	}
	return 0;
}

// 这个函数的名字最好换一下
static int tls12_select_parameters(TLS_CONNECT *conn,
	const int *common_cipher_suites, size_t common_cipher_suites_cnt,
	const int *common_supported_groups, size_t common_supported_groups_cnt,
	const int *common_signature_algorithms, size_t common_signature_algorithms_cnt,
	const int *signature_algorithms_cert, size_t signature_algorithms_cert_cnt,
	const uint8_t *host_name, size_t host_name_len)
{
	const uint8_t *cert_chains = conn->ctx->cert_chains;
	size_t cert_chains_len = conn->ctx->cert_chains_len;
	size_t cert_chain_idx;

	if (!conn || !common_cipher_suites || !common_cipher_suites_cnt
		|| !common_supported_groups || !common_supported_groups_cnt
		|| !common_signature_algorithms || !common_signature_algorithms_cnt) {
		error_print();
		return -1;
	}
	if (!cert_chains || !cert_chains_len) {
		error_print();
		return -1;
	}

	for (cert_chain_idx = 1; cert_chains_len; cert_chain_idx++) {
		const uint8_t *cert_chain;
		size_t cert_chain_len;
		const uint8_t *cert;
		size_t certlen;
		int cert_group;
		size_t i;
		int ret;

		if (tls_uint24array_from_bytes(&cert_chain, &cert_chain_len,
			&cert_chains, &cert_chains_len) != 1) {
			error_print();
			return -1;
		}
		if (tls12_cert_chain_get_end_entity_group(cert_chain, cert_chain_len, &cert_group) != 1) {
			error_print();
			return -1;
		}
		if (!tls_type_is_in_list(cert_group, common_supported_groups, common_supported_groups_cnt)) {
			continue;
		}
		if (x509_certs_get_cert_by_index(cert_chain, cert_chain_len, 0, &cert, &certlen) != 1) {
			error_print();
			return -1;
		}
		if (host_name && host_name_len) {
			if ((ret = tls_cert_match_server_name(cert, certlen, host_name, host_name_len)) < 0) {
				error_print();
				return -1;
			} else if (ret == 0) {
				continue;
			}
		}
		if (signature_algorithms_cert && signature_algorithms_cert_cnt) {
			if ((ret = tls_cert_chain_match_signature_algorithms_cert(cert_chain, cert_chain_len,
				signature_algorithms_cert, signature_algorithms_cert_cnt)) < 0) {
				error_print();
				return -1;
			} else if (ret == 0) {
				continue;
			}
		}

		for (i = 0; i < common_cipher_suites_cnt; i++) {
			size_t j;
			int cipher_suite = common_cipher_suites[i];
			int key_exchange_group;

			if (!tls12_cipher_suite_match_cert_group(cipher_suite, cert_group)) {
				continue;
			}
			if ((ret = tls12_select_key_exchange_group(common_supported_groups,
				common_supported_groups_cnt, cipher_suite, &key_exchange_group)) < 0) {
				error_print();
				return -1;
			} else if (ret == 0) {
				continue;
			}

			for (j = 0; j < common_signature_algorithms_cnt; j++) {
				int sig_alg = common_signature_algorithms[j];

				if (!tls12_signature_scheme_match_cert_group(sig_alg, cert_group)) {
					continue;
				}
				if (!tls12_signature_scheme_match_cipher_suite(sig_alg, cipher_suite)) {
					continue;
				}

				conn->cipher_suite = cipher_suite;
				conn->cert_chain = cert_chain;
				conn->cert_chain_len = cert_chain_len;
				conn->cert_chain_idx = cert_chain_idx;
				conn->sig_alg = sig_alg;
				conn->key_exchange_group = key_exchange_group;
				return 1;
			}
		}
	}

	warning_print();
	return 0;
}

int tls12_record_set_handshake_server_key_exchange(uint8_t *record, size_t *recordlen,
	int server_key_exchange_alg, const uint8_t *server_ecdh_params, size_t server_ecdh_params_len,
	int sig_alg, const uint8_t *sig, size_t siglen)
{
	const int type = TLS_handshake_server_key_exchange;
	uint8_t *p = tls_handshake_data(tls_record_data(record));
	size_t len = 0;

	if (!record || !recordlen || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (!tls_signature_scheme_name(sig_alg)) {
		error_print();
		return -1;
	}
	if (siglen > TLS_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}

	switch (server_key_exchange_alg) {
	case TLS_server_key_exchange_ecdhe:
		if (!server_ecdh_params || !server_ecdh_params_len) {
			error_print();
			return -1;
		}
		tls_array_to_bytes(server_ecdh_params, server_ecdh_params_len, &p, &len);
		break;
	case TLS_server_key_exchange_ecc:
		if (server_ecdh_params || server_ecdh_params_len) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	tls_uint16_to_bytes((uint16_t)sig_alg, &p, &len);
	tls_uint16array_to_bytes(sig, siglen, &p, &len);

	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls12_record_get_handshake_server_key_exchange(const uint8_t *record,
	int server_key_exchange_alg, const uint8_t **server_ecdh_params, size_t *server_ecdh_params_len,
	int *sig_alg, const uint8_t **sig, size_t *siglen)
{
	int type;
	const uint8_t *p;
	size_t len;
	uint16_t alg;

	if (!record || !sig_alg || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_server_key_exchange) {
		error_print();
		return 0;
	}

	switch (server_key_exchange_alg) {
	case TLS_server_key_exchange_ecdhe:
		if (!server_ecdh_params || !server_ecdh_params_len) {
			error_print();
			return -1;
		}
		*server_ecdh_params = p;
		*server_ecdh_params_len = len;
		{
			int key_exchange_group;
			const uint8_t *key_exchange;
			size_t key_exchange_len;

			if (tls_server_ecdh_params_from_bytes(&key_exchange_group,
				&key_exchange, &key_exchange_len, &p, &len) != 1) {
				error_print();
				return -1;
			}
		}
		*server_ecdh_params_len -= len;
		break;

	case TLS_server_key_exchange_ecc:
		if (server_ecdh_params || server_ecdh_params_len) {
			error_print();
			return -1;
		}
		break;

	default:
		error_print();
		return -1;
	}

	if (tls_uint16_from_bytes(&alg, &p, &len) != 1
		|| tls_uint16array_from_bytes(sig, siglen, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (!tls_signature_scheme_name(alg)) {
		error_print();
		return -1;
	}
	if (!siglen) {
		error_print();
		return -1;
	}
	*sig_alg = alg;

	return 1;
}


int tls_recv_client_hello(TLS_CONNECT *conn)
{
	int ret;

	int client_verify = 0;

	int protocol;
	const uint8_t *client_random;
	const uint8_t *session_id;
	size_t session_id_len;
	const uint8_t *cipher_suites;
	size_t cipher_suites_len;
	const uint8_t *exts;
	size_t extslen;
	const uint8_t *ec_point_formats = NULL;
	size_t ec_point_formats_len = 0;
	const uint8_t *supported_groups = NULL;
	size_t supported_groups_len = 0;
	const uint8_t *signature_algorithms = NULL;
	size_t signature_algorithms_len = 0;
	const uint8_t *signature_algorithms_cert = NULL;
	size_t signature_algorithms_cert_len = 0;
	int trusted_ca_keys = 0;
	const uint8_t *trusted_authorities = NULL;
	size_t trusted_authorities_len = 0;
	const uint8_t *server_name = NULL;
	size_t server_name_len = 0;
	const uint8_t *renegotiation_info = NULL;
	size_t renegotiation_info_len = 0;
	int empty_renegotiation_info_scsv = 0;
	int common_cipher_suites[TLS_MAX_CIPHER_SUITES_COUNT];
	size_t common_cipher_suites_cnt = 0;
	int common_supported_groups[32];
	size_t common_supported_groups_cnt = 0;
	int common_signature_algorithms[32];
	size_t common_signature_algorithms_cnt = 0;
	int common_signature_algorithms_cert[32];
	size_t common_signature_algorithms_cert_cnt = 0;
	const int *cert_signature_algorithms = NULL;
	size_t cert_signature_algorithms_cnt = 0;
	const uint8_t *host_name = NULL;
	size_t host_name_len = 0;

	/*
	if (client_verify)
		tls_client_verify_init(&conn->client_verify_ctx);
	*/


	if(conn->verbose) tls_trace("recv ClientHello\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	if (tls_record_protocol(conn->record) != TLS_protocol_tls1) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	if ((ret = tls_record_get_handshake_client_hello(conn->record,
		&protocol, &client_random, &session_id, &session_id_len,
		&cipher_suites, &cipher_suites_len, &exts, &extslen)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (protocol != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	memcpy(conn->client_random, client_random, 32);


	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_ec_point_formats:
		case TLS_extension_supported_groups:
		case TLS_extension_signature_algorithms:
		case TLS_extension_signature_algorithms_cert:
		case TLS_extension_renegotiation_info:
			if (!ext_data) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			break;
		case TLS_extension_trusted_ca_keys:
		case TLS_extension_server_name:
			break;
		}

		switch (ext_type) {
		case TLS_extension_ec_point_formats:
			if (ec_point_formats) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			ec_point_formats = ext_data;
			ec_point_formats_len = ext_datalen;
			break;
		case TLS_extension_supported_groups:
			if (supported_groups) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			supported_groups = ext_data;
			supported_groups_len = ext_datalen;
			break;
		case TLS_extension_signature_algorithms:
			if (signature_algorithms) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms = ext_data;
			signature_algorithms_len = ext_datalen;
			break;
		case TLS_extension_signature_algorithms_cert:
			if (signature_algorithms_cert) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms_cert = ext_data;
			signature_algorithms_cert_len = ext_datalen;
			break;
		case TLS_extension_trusted_ca_keys:
			if (trusted_ca_keys) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (tls_trusted_authorities_from_bytes(&trusted_authorities,
				&trusted_authorities_len, ext_data, ext_datalen) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			trusted_ca_keys = 1;
			break;
		case TLS_extension_server_name:
			if (server_name) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			server_name = ext_data;
			server_name_len = ext_datalen;
			break;
		case TLS_extension_renegotiation_info:
			if (renegotiation_info) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			renegotiation_info = ext_data;
			renegotiation_info_len = ext_datalen;
			break;
		default:
			warning_print();
		}
	}

	if ((ret = tls12_cipher_suites_include_empty_renegotiation_info_scsv(
		cipher_suites, cipher_suites_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 1) {
		empty_renegotiation_info_scsv = 1;
	}

	if (renegotiation_info && empty_renegotiation_info_scsv) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}
	if (renegotiation_info) {
		if ((ret = tls12_renegotiation_info_ext_is_empty(
			renegotiation_info, renegotiation_info_len)) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}
	if (conn->ctx->renegotiation_info && (renegotiation_info || empty_renegotiation_info_scsv)) {
		conn->secure_renegotiation = 1;
	}

	if (ec_point_formats) {
		if ((ret = tls_ec_point_formats_support_uncompressed(ec_point_formats, ec_point_formats_len)) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		conn->ec_point_formats = 1;
	}

	if (trusted_ca_keys) {
		conn->trusted_ca_keys = 1;
		if (trusted_authorities_len > sizeof(conn->trusted_authorities)) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (trusted_authorities_len) {
			memcpy(conn->trusted_authorities, trusted_authorities, trusted_authorities_len);
		}
		conn->trusted_authorities_len = trusted_authorities_len;
	}

	if ((ret = tls12_select_common_cipher_suites(cipher_suites, cipher_suites_len,
		conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt,
		common_cipher_suites, &common_cipher_suites_cnt,
		sizeof(common_cipher_suites)/sizeof(common_cipher_suites[0]))) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}

	if (supported_groups) {
		if ((ret = tls_process_supported_groups(supported_groups, supported_groups_len,
			conn->ctx->supported_groups, conn->ctx->supported_groups_cnt,
			common_supported_groups, &common_supported_groups_cnt,
			sizeof(common_supported_groups)/sizeof(common_supported_groups[0]))) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_handshake_failure);
			return -1;
		}
	} else {
		if (!conn->ctx->supported_groups_cnt) {
			error_print();
			tls_send_alert(conn, TLS_alert_handshake_failure);
			return -1;
		}
		memcpy(common_supported_groups, conn->ctx->supported_groups,
			conn->ctx->supported_groups_cnt * sizeof(conn->ctx->supported_groups[0]));
		common_supported_groups_cnt = conn->ctx->supported_groups_cnt;
	}

	if (signature_algorithms) {
		if ((ret = tls_process_signature_algorithms(signature_algorithms, signature_algorithms_len,
			conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
			common_signature_algorithms, &common_signature_algorithms_cnt,
			sizeof(common_signature_algorithms)/sizeof(common_signature_algorithms[0]))) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_handshake_failure);
			return -1;
		}
	} else {
		if (!conn->ctx->signature_algorithms_cnt) {
			error_print();
			tls_send_alert(conn, TLS_alert_handshake_failure);
			return -1;
		}
		memcpy(common_signature_algorithms, conn->ctx->signature_algorithms,
			conn->ctx->signature_algorithms_cnt * sizeof(conn->ctx->signature_algorithms[0]));
		common_signature_algorithms_cnt = conn->ctx->signature_algorithms_cnt;
	}

	if (signature_algorithms_cert) {
		if ((ret = tls_process_signature_algorithms(signature_algorithms_cert, signature_algorithms_cert_len,
			conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
			common_signature_algorithms_cert, &common_signature_algorithms_cert_cnt,
			sizeof(common_signature_algorithms_cert)/sizeof(common_signature_algorithms_cert[0]))) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_handshake_failure);
			return -1;
		}
		cert_signature_algorithms = common_signature_algorithms_cert;
		cert_signature_algorithms_cnt = common_signature_algorithms_cert_cnt;
	} else if (signature_algorithms) {
		cert_signature_algorithms = common_signature_algorithms;
		cert_signature_algorithms_cnt = common_signature_algorithms_cnt;
	}

	if (server_name) {
		if (tls_server_name_from_bytes(&host_name, &host_name_len, server_name, server_name_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}
		conn->server_name = 1;
	}

	if ((ret = tls12_select_parameters(conn,
		common_cipher_suites, common_cipher_suites_cnt,
		common_supported_groups, common_supported_groups_cnt,
		common_signature_algorithms, common_signature_algorithms_cnt,
		cert_signature_algorithms, cert_signature_algorithms_cnt,
		host_name, host_name_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}

	if (tls12_cipher_suite_get(conn->cipher_suite, &conn->cipher, &conn->digest) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	if (digest_init(&conn->dgst_ctx, conn->digest) != 1) {
		error_print();
		return -1;
	}
	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "ClientHello", &conn->dgst_ctx);

	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}


	/*
	if (client_verify)
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	*/

	if(conn->verbose) {
		fprintf(stderr, "end of recv_client_hello\n");
	}
	tls_clean_record(conn);
	return 1;
}

int tls_send_server_hello(TLS_CONNECT *conn)
{
	int ret;

	if(conn->verbose) tls_trace("send ServerHello\n");

	if (conn->recordlen == 0) {

		uint8_t exts[512];
		uint8_t *pexts = exts;
		size_t extslen = 0;

		tls_record_set_protocol(conn->record, conn->protocol);

		if (tls_random_generate(conn->server_random) != 1) {
			error_print();
			return -1;
		}

		// extensions in ServerHello
		//	ec_point_formats
		if (conn->ec_point_formats) {
			if (tls_ec_point_formats_ext_to_bytes(ec_point_formats, ec_point_formats_cnt, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// server_name
		if (conn->server_name) {
			if (tls_ext_to_bytes(TLS_extension_server_name, NULL, 0, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// trusted_ca_keys
		if (conn->trusted_ca_keys) {
			if (tls_ext_to_bytes(TLS_extension_trusted_ca_keys, NULL, 0, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// renegotiation_info
		if (conn->secure_renegotiation) {
			uint8_t ext_data[1] = { 0 };

			if (tls_ext_to_bytes(TLS_extension_renegotiation_info,
				ext_data, sizeof(ext_data), &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		if (tls_record_set_handshake_server_hello(conn->record, &conn->recordlen,
			conn->protocol, conn->server_random, NULL, 0,
			conn->cipher_suite,
			exts, extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);


		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "ServerHello", &conn->dgst_ctx);

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (conn->ctx->cacertslen) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}

	tls_clean_record(conn);
	return 1;
}

int tls_recv_server_hello(TLS_CONNECT *conn)
{
	int ret;
	int protocol;
	int cipher_suite;
	const uint8_t *server_random;
	const uint8_t *session_id;
	size_t session_id_len;
	const uint8_t *exts;
	size_t extslen;

	const uint8_t *ec_point_formats = NULL;
	size_t ec_point_formats_len = 0;
	int server_name = 0;
	int trusted_ca_keys = 0;
	int renegotiation_info = 0;

	if(conn->verbose)
		tls_trace("recv ServerHello\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (conn->verbose)
		tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	if ((ret = tls_record_get_handshake_server_hello(conn->record,
		&protocol, &server_random, &session_id, &session_id_len, &cipher_suite,
		&exts, &extslen)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// version
	if (protocol != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	// random
	memcpy(conn->server_random, server_random, 32);

	// session_id
	memcpy(conn->session_id, session_id, session_id_len);
	conn->session_id_len = session_id_len;

	// cipher_suite
	if (tls_type_is_in_list(cipher_suite, conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}
	conn->cipher_suite = cipher_suite;

	if (tls12_cipher_suite_get(conn->cipher_suite, &conn->cipher, &conn->digest) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	if (digest_init(&conn->dgst_ctx, conn->digest) != 1) {
		error_print();
		return -1;
	}


	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_ec_point_formats:
			if (ec_point_formats) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			ec_point_formats = ext_data;
			ec_point_formats_len = ext_datalen;
			break;
		case TLS_extension_server_name:
			if (!conn->server_name || server_name || ext_datalen) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			server_name = 1;
			break;
		case TLS_extension_trusted_ca_keys:
			if (!conn->ctx->trusted_ca_keys || trusted_ca_keys || ext_datalen) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			trusted_ca_keys = 1;
			conn->trusted_ca_keys = 1;
			break;
		case TLS_extension_renegotiation_info:
			if ((!conn->ctx->renegotiation_info && !conn->ctx->empty_renegotiation_info_scsv)
				|| renegotiation_info) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if ((ret = tls12_renegotiation_info_ext_is_empty(ext_data, ext_datalen)) < 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			} else if (ret == 0) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			renegotiation_info = 1;
			conn->secure_renegotiation = 1;
			break;
		default:
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	if ((conn->ctx->renegotiation_info || conn->ctx->empty_renegotiation_info_scsv)
		&& !renegotiation_info) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}

	if (ec_point_formats) {
		if ((ret = tls_ec_point_formats_support_uncompressed(ec_point_formats, ec_point_formats_len)) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
	}

	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "ClientHello", &conn->dgst_ctx);

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "ServerHello", &conn->dgst_ctx);

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}


	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	return 1;
}

int tls_send_server_certificate(TLS_CONNECT *conn)
{
	int ret;

	if (conn->verbose) tls_trace("send ServerCertificate\n");

	if (conn->recordlen == 0) {
		if (tls_record_set_handshake_certificate(conn->record, &conn->recordlen,
			conn->cert_chain, conn->cert_chain_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if (conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "Certificate", &conn->dgst_ctx);
		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	return 1;
}

int tls_recv_server_certificate(TLS_CONNECT *conn)
{
	int ret;
	int verify_result = 0;
	const uint8_t *server_cert;
	size_t server_cert_len;
	X509_KEY server_sign_key;
	int server_sig_alg = 0;
	int server_group;
	int cert_sig_alg = 0;
	const int *signature_algorithms_cert = NULL;
	size_t signature_algorithms_cert_cnt = 0;


	if(conn->verbose)
		tls_trace("recv server Certificate\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if(conn->verbose)
		tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if ((ret = tls_record_get_handshake_certificate(conn->record,
		conn->peer_cert_chain, &conn->peer_cert_chain_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return 0;
	}
	if (!conn->peer_cert_chain_len) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if(conn->verbose)
		tls_handshake_digest_print(stderr, 0, 0, "Certificate", &conn->dgst_ctx);
	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}


	// server_sign_key
	if (x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len, 0,
		&server_cert, &server_cert_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	if (x509_cert_get_subject_public_key(server_cert, server_cert_len, &server_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	if (tls12_public_key_get_group(&server_sign_key, &server_group) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	// check server certificate matches negotiated cipher_suite
	if (!tls12_cipher_suite_match_cert_group(conn->cipher_suite, server_group)) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	switch (conn->cipher_suite) {
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecc_sm4_gcm_sm3:
		server_sig_alg = TLS_sig_sm2sig_sm3;
		break;
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
#ifdef ENABLE_AES_CCM
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm:
#endif
		server_sig_alg = TLS_sig_ecdsa_secp256r1_sha256;
		break;
	default:
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	// check server certificate matches ClientHello.supported_groups
	if (conn->ctx->supported_groups_cnt) {
		if (!tls_type_is_in_list(server_group, conn->ctx->supported_groups,
			conn->ctx->supported_groups_cnt)) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
	}

	// check server certificate matches ClientHello.signature_algorithms
	if (conn->ctx->signature_algorithms_cnt) {
		if ((ret = tls_cert_match_signature_algorithms(server_cert, server_cert_len,
			conn->ctx->signature_algorithms,
			conn->ctx->signature_algorithms_cnt,
			&cert_sig_alg)) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
		if (!tls12_signature_scheme_match_cert_group(cert_sig_alg, server_group)
			|| !tls12_signature_scheme_match_cipher_suite(cert_sig_alg, conn->cipher_suite)) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
		server_sig_alg = cert_sig_alg;
	}

	// check certificate-chain signatures match ClientHello.signature_algorithms_cert
	if (conn->signature_algorithms_cert) {
		signature_algorithms_cert = conn->ctx->signature_algorithms;
		signature_algorithms_cert_cnt = conn->ctx->signature_algorithms_cnt;
	} else if (conn->ctx->signature_algorithms_cnt) {
		signature_algorithms_cert = conn->ctx->signature_algorithms;
		signature_algorithms_cert_cnt = conn->ctx->signature_algorithms_cnt;
	}
	if (signature_algorithms_cert && signature_algorithms_cert_cnt) {
		if ((ret = tls_cert_chain_match_signature_algorithms_cert(
			conn->peer_cert_chain, conn->peer_cert_chain_len,
			signature_algorithms_cert, signature_algorithms_cert_cnt)) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
	}

	// check server certificate matches ClientHello.server_name
	if (conn->server_name) {
		if ((ret = tls_cert_match_server_name(server_cert, server_cert_len,
			conn->host_name, conn->host_name_len)) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
	}

	conn->signature_algorithms[0] = server_sig_alg;
	conn->signature_algorithms_cnt = 1;

	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	assert(conn->ctx->verify_depth > 0 && conn->ctx->verify_depth < 10);

	// verify server Certificate
	if (conn->ctx->cacertslen) {
		if (x509_certs_verify(conn->peer_cert_chain, conn->peer_cert_chain_len, X509_cert_chain_server,
			conn->ctx->cacerts, conn->ctx->cacertslen, conn->ctx->verify_depth, &verify_result) != 1) {
			error_print();
			conn->verify_result = verify_result;
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
	}
	conn->verify_result = verify_result;

	return 1;
}

int tls_send_server_key_exchange(TLS_CONNECT *conn)
{
	int ret;

	if(conn->verbose) tls_trace("send ServerKeyExchange\n");

	if (conn->recordlen == 0) {
		int curve_oid = tls_named_curve_oid(conn->key_exchange_group);
		X509_KEY *sign_key = &conn->ctx->x509_keys[conn->cert_chain_idx - 1];
		uint8_t server_ecdh_params[69];
		uint8_t *p = server_ecdh_params;
		size_t server_ecdh_params_len = 0;
		X509_SIGN_CTX sign_ctx;
		const void *sign_args = NULL;
		size_t sign_argslen = 0;
		uint8_t sig[X509_SIGNATURE_MAX_SIZE];
		size_t siglen;

		// generate server ecdh_key
		if (x509_key_generate(&conn->key_exchanges[0], OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
			error_print();
			return -1;
		}

		if (tls_server_ecdh_params_to_bytes(&conn->key_exchanges[0],
			&p, &server_ecdh_params_len) != 1) {
			error_print();
			return -1;
		}
		if (server_ecdh_params_len != sizeof(server_ecdh_params)) {
			error_print();
			return -1;
		}

		// sign server_ecdh_params
		if (sign_key->algor == OID_ec_public_key && sign_key->algor_param == OID_sm2) {
			sign_args = SM2_DEFAULT_ID;
			sign_argslen = SM2_DEFAULT_ID_LENGTH;
		}
		if (x509_sign_init(&sign_ctx, sign_key, sign_args, sign_argslen) != 1
			|| x509_sign_update(&sign_ctx, conn->client_random, 32) != 1
			|| x509_sign_update(&sign_ctx, conn->server_random, 32) != 1
			|| x509_sign_update(&sign_ctx, server_ecdh_params, server_ecdh_params_len) != 1
			|| x509_sign_finish(&sign_ctx, sig, &siglen) != 1) {
			x509_sign_ctx_cleanup(&sign_ctx);
			error_print();
			return -1;
		}
		x509_sign_ctx_cleanup(&sign_ctx);

		if (tls12_record_set_handshake_server_key_exchange(conn->record, &conn->recordlen,
			TLS_server_key_exchange_ecdhe, server_ecdh_params, server_ecdh_params_len,
			conn->sig_alg, sig, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "ServerKeyExchange", &conn->dgst_ctx);

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	return 1;
}

// match the ecdhe of cipher_suite
int tls_curve_match_cipher_suite(int named_curve, int cipher_suite)
{
	switch (named_curve) {
	case TLS_curve_sm2p256v1:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_sm4_cbc_sm3:
		case TLS_cipher_ecdhe_sm4_gcm_sm3:
			break;
		default:
			error_print();
			return -1;
		}
		break;
	case TLS_curve_secp256r1:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
#ifdef ENABLE_AES_CCM
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm:
#endif
			break;
		default:
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int tls_signature_scheme_match_cipher_suite(int sig_alg, int cipher_suite)
{
	switch (sig_alg) {
	case TLS_sig_sm2sig_sm3:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_sm4_cbc_sm3:
		case TLS_cipher_ecdhe_sm4_gcm_sm3:
		case TLS_cipher_ecc_sm4_cbc_sm3:
		case TLS_cipher_ecc_sm4_gcm_sm3:
			break;
		default:
			error_print();
			return -1;
		}
		break;
	case TLS_sig_ecdsa_secp256r1_sha256:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
#ifdef ENABLE_AES_CCM
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm:
#endif
			break;
		default:
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int tls_recv_server_key_exchange(TLS_CONNECT *conn)
{
	int ret;

	// 这部分是被签名的值，必须要拿到
	const uint8_t *server_ecdh_params;
	size_t server_ecdh_params_len;


	const uint8_t *server_key_exchange;
	size_t server_key_exchange_len;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;

	// verify ServerKeyExchange
	X509_KEY server_sign_key;

	int server_cert_index = 0;
	const uint8_t *server_cert;
	size_t server_cert_len;

	X509_SIGN_CTX sign_ctx;
	const void *sign_args = NULL;
	size_t sign_argslen = 0;

	if(conn->verbose) tls_trace("recv ServerKeyExchange\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);


	if ((ret = tls12_record_get_handshake_server_key_exchange(conn->record,
		TLS_server_key_exchange_ecdhe, &server_ecdh_params, &server_ecdh_params_len,
		&sig_alg, &sig, &siglen)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return 0;
	}
	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if(conn->verbose)
		tls_handshake_digest_print(stderr, 0, 0, "ServerKeyExchange", &conn->dgst_ctx);

	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}

	if (tls_signature_scheme_match_cipher_suite(sig_alg, conn->cipher_suite) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	if (conn->client_certs_len)
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);


	if (x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len,
		server_cert_index, &server_cert, &server_cert_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	if (x509_cert_get_subject_public_key(server_cert, server_cert_len, &server_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	switch (sig_alg) {
	case TLS_sig_sm2sig_sm3:
		if (server_sign_key.algor != OID_ec_public_key
			|| server_sign_key.algor_param != OID_sm2) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
		break;
	case TLS_sig_ecdsa_secp256r1_sha256:
		if (server_sign_key.algor != OID_ec_public_key
			|| server_sign_key.algor_param != OID_secp256r1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	if (server_sign_key.algor == OID_ec_public_key && server_sign_key.algor_param == OID_sm2) {
		sign_args = SM2_DEFAULT_ID;
		sign_argslen = SM2_DEFAULT_ID_LENGTH;
	}

	if (x509_verify_init(&sign_ctx, &server_sign_key, sign_args, sign_argslen, sig, siglen) != 1
		|| x509_verify_update(&sign_ctx, conn->client_random, 32) != 1
		|| x509_verify_update(&sign_ctx, conn->server_random, 32) != 1
		|| x509_verify_update(&sign_ctx, server_ecdh_params, server_ecdh_params_len) != 1
		|| x509_verify_finish(&sign_ctx) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}

	if(conn->verbose) {
		fprintf(stderr, ">>>>>> ServerKeyExchange verify success\n");
	}

	if (tls_server_ecdh_params_from_bytes(&conn->key_exchange_group,
		&server_key_exchange, &server_key_exchange_len,
		&server_ecdh_params, &server_ecdh_params_len) != 1
		|| tls_length_is_zero(server_ecdh_params_len) != 1) {
		error_print();
		return -1;
	}
	if (server_key_exchange_len != sizeof(conn->peer_key_exchange)) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	if (tls_curve_match_cipher_suite(conn->key_exchange_group, conn->cipher_suite) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}

	memcpy(conn->peer_key_exchange, server_key_exchange, server_key_exchange_len);
	conn->peer_key_exchange_len = server_key_exchange_len;


	return 1;
}

int tls12_send_certificate_request(TLS_CONNECT *conn)
{
	int ret;

	// 如果要进行客户端证书验证，服务器要提供验证的证书，但是所有证书的
	const uint8_t cert_types[] = { TLS_cert_type_ecdsa_sign };
	uint8_t ca_names[TLS_MAX_CA_NAMES_SIZE] = {0}; // TODO: 根据客户端验证CA证书列计算缓冲大小，或直接输出到record缓冲
	size_t ca_names_len = 0;


	if (!conn->client_certificate_verify) {
		error_print();
		return -1;
	}

	if (conn->recordlen == 0) {
		if(conn->verbose) tls_trace("send CertificateRequest\n");
		if (tls_authorities_from_certs(ca_names, &ca_names_len, sizeof(ca_names),
			conn->ctx->cacerts, conn->ctx->cacertslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (tls12_record_set_handshake_certificate_request(conn->record, &conn->recordlen,
			cert_types, sizeof(cert_types),
			NULL, 0, // TODO: 这里需要至少添加TLS_cert_type_ecdsa_sign					
			ca_names, ca_names_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	return 1;
}

int tls12_recv_certificate_request(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;
	const uint8_t *cp;
	size_t len;
	int handshake_type;

	const uint8_t *cert_types;
	size_t cert_types_len;
	const uint8_t *sig_algs;
	size_t sig_algs_len;
	const uint8_t *ca_names;
	size_t ca_names_len;

	if(conn->verbose) tls_trace("recv CertificateRequest*\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (tls_record_get_handshake(record, &handshake_type, &cp, &len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (handshake_type != TLS_handshake_certificate_request) {
		if(conn->verbose) tls_trace("    no CertificateRequest\n");
		return 0; // 表明对方没有发送预期的报文
	}
	if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);


	if (tls12_record_get_handshake_certificate_request(conn->record,
		&cert_types, &cert_types_len, &sig_algs, &sig_algs_len, &ca_names, &ca_names_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}

	if (tls_cert_types_has_ecdsa_sign(cert_types, cert_types_len) != 1
		|| tls_authorities_issued_certificate(ca_names, ca_names_len, conn->client_certs, conn->client_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unsupported_certificate);
		return -1;
	}

	sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

	conn->recordlen = 0;
	return 1;
}

int tls_send_server_hello_done(TLS_CONNECT *conn)
{
	int ret;
	if(conn->verbose) tls_trace("send ServerHelloDone\n");


	if (conn->recordlen == 0) {
		tls_record_set_handshake_server_hello_done(conn->record, &conn->recordlen);
		if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);


		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "ServerHelloDone", &conn->dgst_ctx);
		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}
	}


	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (conn->client_certs_len) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}
	return 1;
}

// 这是一个非常特殊的状态，其他的所有recv状态都是要读取的
// 但是这个状态在大多数情况下，之前已经读取完了，但是我们无法判断这个信息
int tls_recv_server_hello_done(TLS_CONNECT *conn)
{
	int ret;
	if(conn->verbose) tls_trace("recv ServerHelloDone\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	if (tls_record_get_handshake_server_hello_done(conn->record) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "ServerHelloDone", &conn->dgst_ctx);

	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}


	if (conn->client_certs_len)
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);


	return 1;
}

int tls_send_client_certificate(TLS_CONNECT *conn)
{
	int ret;
	if(conn->verbose) tls_trace("send ClientCertificate\n");

	if (conn->client_certs_len == 0) {
		error_print();
		return -1;
	}

	if (conn->recordlen == 0) {
		if (tls_record_set_handshake_certificate(conn->record, &conn->recordlen,
			conn->client_certs, conn->client_certs_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "client Certificate", &conn->dgst_ctx);

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}


	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

// 只有在需要验证客户端证书的时候这个函数才执行，是否内部要判断一下
int tls_recv_client_certificate(TLS_CONNECT *conn)
{
	int ret;
	const int verify_depth = 5;
	int verify_result;

	if(conn->verbose) tls_trace("recv ClientCertificate\n");

	if (conn->ctx->cacertslen == 0) {
		error_print();
		return -1;
	}

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) { // protocol检查应该在trace之后
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);
	if (tls_record_get_handshake_certificate(conn->record, conn->client_certs, &conn->client_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (x509_certs_verify(conn->client_certs, conn->client_certs_len, X509_cert_chain_client,
		conn->ctx->cacerts, conn->ctx->cacertslen, verify_depth, &verify_result) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}


		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "client Certificate", &conn->dgst_ctx);

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}


	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

int tls_send_client_key_exchange(TLS_CONNECT *conn)
{
	int ret;

	if (conn->recordlen == 0) {
		uint8_t point_octets[65];
		uint8_t *point_octets_ptr = point_octets;
		size_t point_octets_len = 0;
		int curve_oid = tls_named_curve_oid(conn->key_exchange_group);

		if (conn->verbose)
			tls_trace("send ClientKeyExchange\n");


		if (x509_key_generate(&conn->key_exchanges[0], OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
			error_print();
			return -1;
		}
		if (x509_public_key_to_bytes(&conn->key_exchanges[0], &point_octets_ptr, &point_octets_len) != 1) {
			error_print();
			return -1;
		}
		if (point_octets_len != sizeof(point_octets)) {
			error_print();
			return -1;
		}
		if (tls12_record_set_handshake_client_key_exchange(conn->record, &conn->recordlen,
			point_octets, point_octets_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (conn->verbose)
			tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if (conn->verbose)
			tls_handshake_digest_print(stderr, 0, 0, "ClientKeyExchange", &conn->dgst_ctx);

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}

		if (conn->client_certs_len) {
			sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
		}

		if (tls_derive_pre_master_secret(conn) != 1
			|| tls_derive_master_secret(conn) != 1
			|| tls_derive_key_block(conn) != 1
			|| tls_init_application_keys(conn) != 1) {
			error_print();
			return -1;
		}
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	return 1;
}

int tls_recv_client_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *point_octets;
	size_t point_octets_len;

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (conn->verbose)
		tls_trace("recv ClientKeyExchange\n");

	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (conn->verbose)
		tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if (conn->verbose)
		tls_handshake_digest_print(stderr, 0, 0, "ClientKeyExchange", &conn->dgst_ctx);

	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}

	if (tls12_record_get_handshake_client_key_exchange(conn->record,
		&point_octets, &point_octets_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (point_octets_len != 65) {
		error_print();
		return -1;
	}
	memcpy(conn->peer_key_exchange, point_octets, point_octets_len);
	conn->peer_key_exchange_len = point_octets_len;

	if (tls_derive_pre_master_secret(conn) != 1
		|| tls_derive_master_secret(conn) != 1
		|| tls_derive_key_block(conn) != 1
		|| tls_init_application_keys(conn) != 1) {
		error_print();
		return -1;
	}

	if (conn->ctx->cacertslen) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}

	return 1;
}


int tls_send_certificate_verify(TLS_CONNECT *conn)
{
	int ret;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	if (conn->verbose)
		tls_trace("send CertificateVerify\n");

	if (conn->recordlen == 0) {
		X509_KEY *sign_key = &conn->ctx->x509_keys[conn->cert_chain_idx - 1];
		X509_SIGN_CTX sign_ctx;
		const uint8_t *signer_id = NULL;
		size_t signer_idlen = 0;

		if (sign_key->algor == OID_ec_public_key && sign_key->algor_param == OID_sm2) {
			signer_id = (uint8_t *)SM2_DEFAULT_ID;
			signer_idlen = SM2_DEFAULT_ID_LENGTH;
		}

		if (x509_sign_init(&sign_ctx, sign_key, signer_id, signer_idlen) != 1
			|| x509_sign_update(&sign_ctx, conn->transcript, conn->transcript_len) != 1
			|| x509_sign_finish(&sign_ctx, sig, &siglen) != 1) {
			gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
			error_print();
			return -1;
		}
		gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));

		if (tls_record_set_handshake_certificate_verify(conn->record, &conn->recordlen, sig, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (conn->verbose)
			tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if (conn->verbose)
			tls_handshake_digest_print(stderr, 0, 0, "ClientKeyExchange", &conn->dgst_ctx);

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}

	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	return 1;
}

int tls_recv_certificate_verify(TLS_CONNECT *conn)
{
	int ret;
	X509_KEY client_sign_key;

	const uint8_t *sig;
	size_t siglen;

	const uint8_t *client_cert;
	size_t client_cert_len;

	if (!conn->client_certificate_verify) {
		error_print();
		return -1;
	}

	if (conn->verbose) tls_trace("recv CertificateVerify\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		tls_send_alert(conn, TLS_alert_unexpected_message);
		error_print();
		return -1;
	}
	if (conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	// get signature from certificate_verify
	if (tls_record_get_handshake_certificate_verify(conn->record, &sig, &siglen) != 1) {
		tls_send_alert(conn, TLS_alert_unexpected_message);
		error_print();
		return -1;
	}

	// get sign_key from client certificate
	if (x509_certs_get_cert_by_index(conn->client_certs, conn->client_certs_len, 0,
		&client_cert, &client_cert_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	if (x509_cert_get_subject_public_key(client_cert, client_cert_len, &client_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	// 这里是否要验证证书的类型呢？我们现在还不支持其他签名算法
	if (client_sign_key.algor != OID_ec_public_key
		|| client_sign_key.algor_param != OID_sm2) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}



	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int tls_send_change_cipher_spec(TLS_CONNECT *conn)
{
	int ret;
	if (conn->recordlen == 0) {
		if(conn->verbose) tls_trace("send [ChangeCipherSpec]\n");
		if (tls_record_set_change_cipher_spec(conn->record, &conn->recordlen) !=1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);
	}
	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}
	return 1;
}

int tls_recv_change_cipher_spec(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if(conn->verbose)
		tls_trace("recv [ChangeCipherSpec]\n");

	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		if (conn->is_client && conn->handshake_state == TLS_state_server_change_cipher_spec)
			tls12_send_alert(conn, TLS_alert_unexpected_message);
		else	tls_send_alert(conn, TLS_alert_unexpected_message);

		return -1;
	}
	if (conn->verbose)
		tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	if (tls_record_get_change_cipher_spec(conn->record) != 1) {
		error_print();
		if (conn->is_client && conn->handshake_state == TLS_state_server_change_cipher_spec)
			tls12_send_alert(conn, TLS_alert_unexpected_message);
		else	tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	return 1;
}

int tls_send_client_finished(TLS_CONNECT *conn)
{
	int ret;


	if (conn->recordlen == 0) {
		if(conn->verbose) tls_trace("send client {Finished}\n");

		uint8_t local_verify_data[12];

		if (tls_compute_verify_data(conn->digest, conn->master_secret,
			"client finished", &conn->dgst_ctx, local_verify_data) != 1) {
			error_print();
			tls12_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		tls_record_set_protocol(conn->plain_record, conn->protocol);

		if (tls_record_set_handshake_finished(conn->plain_record, &conn->plain_recordlen,
			local_verify_data, sizeof(local_verify_data)) != 1) {
			error_print();
			tls12_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->plain_record, conn->plain_recordlen);

		if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "Finished", &conn->dgst_ctx);

		if (tls_update_transcript(conn, conn->plain_record) != 1) {
			error_print();
			return -1;
		}

		if (tls_record_encrypt(conn->cipher_suite,
			&conn->client_write_mac_ctx, &conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, conn->plain_record, conn->plain_recordlen,
			conn->record, &conn->recordlen) != 1) {

			error_print();
			tls12_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls_seq_num_incr(conn->client_seq_num);

		if (conn->verbose >= 5) {
			format_bytes(stderr, 0, 0, "encrypted finsished ..... ", conn->record, conn->recordlen);
		}
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	return 1;
}

int tls_recv_client_finished(TLS_CONNECT *conn)
{
	int ret;

	const uint8_t *verify_data;
	size_t verify_data_len;
	uint8_t local_verify_data[12];

	if (tls_compute_verify_data(conn->digest, conn->master_secret, "client finished",
		&conn->dgst_ctx, local_verify_data) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	if (conn->verbose >= 5) {
		format_bytes(stderr, 0, 0, "verify_data", local_verify_data, 12);
	}


	// recv ClientFinished
	if(conn->verbose) tls_trace("recv client {Finished}\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	//tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	if (conn->verbose >= 5) {
		format_bytes(stderr, 0, 0, "Finished", conn->record, conn->recordlen);
	}


	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// decrypt ClientFinished
	if(conn->verbose) tls_trace(">>>>>>>decrypt Finished\n");


	if (conn->verbose >= 5) {
		format_bytes(stderr, 0, 0, "client_seq_num", conn->client_seq_num, 8);
	}

	if (tls_record_decrypt(conn->cipher_suite, &conn->client_write_mac_ctx, &conn->client_write_key,
		conn->client_write_iv, conn->client_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls_seq_num_incr(conn->client_seq_num);



	if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->plain_record, conn->plain_recordlen);

	if (tls_record_get_handshake_finished(conn->plain_record, &verify_data, &verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	if (verify_data_len != sizeof(local_verify_data)) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}


	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "client Finished", &conn->dgst_ctx);

	if (tls_update_transcript(conn, conn->plain_record) != 1) {
		error_print();
		return -1;
	}

	// verify ClientFinished


	if (memcmp(verify_data, local_verify_data, sizeof(local_verify_data)) != 0) {
		error_puts("client_finished.verify_data verification failure");
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}

	return 1;
}

int tls_send_server_finished(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;
	size_t recordlen;
	uint8_t local_verify_data[12];


	tls_record_set_protocol(conn->plain_record, conn->protocol);

	if (conn->recordlen == 0) {
		if(conn->verbose) tls_trace("send server Finished\n");

		if (tls_compute_verify_data(conn->digest, conn->master_secret,
			"server finished", &conn->dgst_ctx, local_verify_data) != 1) {
			error_print();
			tls12_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		if (conn->verbose >= 5) {
			format_bytes(stderr, 0, 0, "server verify_data", local_verify_data, 12);
		}

		if (tls_record_set_handshake_finished(conn->plain_record, &conn->plain_recordlen,
			local_verify_data, sizeof(local_verify_data)) != 1) {
			error_print();
			tls12_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->plain_record, conn->plain_recordlen);

		if (tls_record_encrypt(conn->cipher_suite,
			&conn->server_write_mac_ctx, &conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->plain_record, conn->plain_recordlen,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			tls12_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls_seq_num_incr(conn->server_seq_num);

	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	return 1;
}

int tls_recv_server_finished(TLS_CONNECT *conn)
{
	int ret;
	uint8_t finished_record[TLS_FINISHED_RECORD_BUF_SIZE];
	size_t finished_record_len;

	const uint8_t *verify_data;
	size_t verify_data_len;
	uint8_t local_verify_data[12];

	if (tls_compute_verify_data(conn->digest, conn->master_secret,
		"server finished", &conn->dgst_ctx, local_verify_data) != 1) {
		error_print();
		tls12_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	if (conn->verbose >= 5) {
		format_bytes(stderr, 0, 0, ">>> verify_data", local_verify_data, 12);
	}

	// Finished
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if(conn->verbose)
		tls_trace("recv server Finished\n");

	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls12_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if(conn->verbose) tls_trace("decrypt Finished\n");

	if (conn->verbose >= 5) {
		format_bytes(stderr, 0, 0, "server_seq_num", conn->server_seq_num, 8);
	}

	if (tls_record_decrypt(conn->cipher_suite, &conn->server_write_mac_ctx, &conn->server_write_key,
		conn->server_write_iv, conn->server_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls12_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	if(conn->verbose)
		tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->plain_record, conn->plain_recordlen);

	tls_seq_num_incr(conn->server_seq_num);

	if (tls_record_get_handshake_finished(conn->plain_record, &verify_data, &verify_data_len) != 1) {
		error_print();
		tls12_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (verify_data_len != sizeof(local_verify_data)) {
		error_print();
		tls12_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}


	if (memcmp(verify_data, local_verify_data, sizeof(local_verify_data)) != 0) {
		error_puts("server_finished.verify_data verification failure");
		tls12_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}

	return 1;
}

int tls12_send(TLS_CONNECT *conn, const uint8_t *in, size_t inlen, size_t *sentlen)
{
	const HMAC_CTX *hmac_ctx;
	const BLOCK_CIPHER_KEY *enc_key;
	const uint8_t *fixed_iv;
	uint8_t *seq_num;
	size_t recordlen;
	int ret;

	if (!conn) {
		error_print();
		return -1;
	}
	if (!in || !inlen || !sentlen) {
		error_print();
		return -1;
	}
	if (conn->recv_state) {
		*sentlen = 0;
		return TLS_ERROR_RECV_AGAIN;
	}
	if (conn->send_state && conn->send_state != TLS_state_send_record) {
		error_print();
		return -1;
	}

	*sentlen = 0;

	if (!conn->recordlen) {

		if (inlen > TLS_MAX_PLAINTEXT_SIZE) {
			inlen = TLS_MAX_PLAINTEXT_SIZE;
		}

		if (conn->datalen) {
			error_puts("recv all buffered data before send");
			return -1;
		}

		if (conn->is_client) {
			hmac_ctx = &conn->client_write_mac_ctx;
			enc_key = &conn->client_write_key;
			fixed_iv = conn->client_write_iv;
			seq_num = conn->client_seq_num;
		} else {
			hmac_ctx = &conn->server_write_mac_ctx;
			enc_key = &conn->server_write_key;
			fixed_iv = conn->server_write_iv;
			seq_num = conn->server_seq_num;
		}

		if (tls_record_set_type(conn->databuf, TLS_record_application_data) != 1
			|| tls_record_set_protocol(conn->databuf, conn->protocol) != 1
			|| tls_record_set_data(conn->databuf, in, inlen) != 1) {
			error_print();
			return -1;
		}
		if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->databuf, tls_record_length(conn->databuf));

		switch (conn->cipher_suite) {
		case TLS_cipher_ecdhe_sm4_cbc_sm3:
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
			if (tls_cbc_encrypt(hmac_ctx, enc_key, seq_num, conn->databuf,
				conn->databuf + 5, tls_record_data_length(conn->databuf),
				conn->record + 5, &recordlen) != 1) {
				error_print();
				return -1;
			}
			break;

		case TLS_cipher_ecdhe_sm4_gcm_sm3:
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
			if (tls_gcm_encrypt(enc_key, fixed_iv, seq_num, conn->databuf,
				conn->databuf + 5, tls_record_data_length(conn->databuf),
				conn->record + 5, &recordlen) != 1) {
				error_print();
				return -1;
			}
			break;

#ifdef ENABLE_AES_CCM
		case TLS_cipher_ecdhe_ecdsa_aes_128_ccm_sha256:
			if (tls_ccm_encrypt(enc_key, fixed_iv, seq_num, conn->databuf,
				conn->databuf + 5, tls_record_data_length(conn->databuf),
				conn->record + 5, &recordlen) != 1) {
				error_print();
				return -1;
			}
			break;
#endif

		default:
			error_print();
			return -1;
		}
		tls_seq_num_incr(seq_num);

		conn->record[0] = conn->databuf[0];
		conn->record[1] = conn->databuf[1];
		conn->record[2] = conn->databuf[2];
		conn->record[3] = (uint8_t)(recordlen >> 8);
		conn->record[4] = (uint8_t)(recordlen);
		recordlen += 5;

		conn->recordlen = recordlen;
		conn->record_offset = 0;
		conn->sentlen = inlen;
		conn->send_state = TLS_state_send_record;
		if(conn->verbose) tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, recordlen);
	}

	ret = tls_send_record(conn);
	if (ret != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	*sentlen = conn->sentlen;
	conn->send_state = 0;
	tls_clean_record(conn);
	return 1;
}

static int tls12_send_alert_ex(TLS_CONNECT *conn, int level, int alert)
{
	const HMAC_CTX *hmac;
	const BLOCK_CIPHER_KEY *key;
	const uint8_t *iv;
	uint8_t *seq_num;
	int ret;

	if (!conn) {
		error_print();
		return -1;
	}
	if (conn->protocol == TLS_protocol_tls13) {
		error_print();
		return -1;
	}
	if (!tls_alert_level_name(level) || !tls_alert_description_text(alert)) {
		error_print();
		return -1;
	}
	if (conn->send_state && conn->send_state != TLS_state_send_record) {
		error_print();
		return -1;
	}
	if (conn->send_state == TLS_state_send_record
		&& tls_record_type(conn->record) != TLS_record_alert) {
		error_print();
		return -1;
	}

	if (!conn->send_state) {
		tls_clean_record(conn);
		conn->plain_recordlen = 0;

		if (conn->is_client) {
			hmac = &conn->client_write_mac_ctx;
			key = &conn->client_write_key;
			iv = conn->client_write_iv;
			seq_num = conn->client_seq_num;
		} else {
			hmac = &conn->server_write_mac_ctx;
			key = &conn->server_write_key;
			iv = conn->server_write_iv;
			seq_num = conn->server_seq_num;
		}

		tls_record_set_protocol(conn->plain_record, conn->protocol);
		if (tls_record_set_alert(conn->plain_record, &conn->plain_recordlen, level, alert) != 1) {
			error_print();
			return -1;
		}
		if (conn->verbose) {
			tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->plain_record, conn->plain_recordlen);
		}

		if (tls_record_encrypt(conn->cipher_suite, hmac, key, iv, seq_num,
			conn->plain_record, conn->plain_recordlen,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			conn->plain_recordlen = 0;
			tls_clean_record(conn);
			return -1;
		}
		tls_seq_num_incr(seq_num);
		conn->record_offset = 0;
		conn->send_state = TLS_state_send_record;

		if (conn->verbose) {
			tls_encrypted_record_print(stderr, conn->record, conn->recordlen, 0, 0);
		}
	}

	ret = tls_send_record(conn);
	if (ret != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	conn->send_state = 0;
	conn->plain_recordlen = 0;
	tls_clean_record(conn);
	return 1;
}

int tls12_send_alert(TLS_CONNECT *conn, int alert)
{
	return tls12_send_alert_ex(conn, TLS_alert_level_fatal, alert);
}

int tls12_send_warning(TLS_CONNECT *conn, int alert)
{
	return tls12_send_alert_ex(conn, TLS_alert_level_warning, alert);
}


/*
      Client                                               Server

      ClientHello                  -------->
                                                      ServerHello
                                                      Certificate
                                                ServerKeyExchange
                                              CertificateRequest*
                                   <--------      ServerHelloDone
      Certificate*
      ClientKeyExchange
      CertificateVerify*
      [ChangeCipherSpec]
      Finished                     -------->
                                               [ChangeCipherSpec]
                                   <--------             Finished
      Application Data             <------->     Application Data

*/

int tls12_do_client_handshake(TLS_CONNECT *conn)
{
	int ret;
	int next_state;

	switch (conn->handshake_state) {
	case TLS_state_client_hello:
		ret = tls_send_client_hello(conn);
		next_state = TLS_state_server_hello;
		break;

	case TLS_state_server_hello:
		ret = tls_recv_server_hello(conn);
		next_state = TLS_state_server_certificate;
		break;

	case TLS_state_server_certificate:
		ret = tls_recv_server_certificate(conn);
		next_state = TLS_state_server_key_exchange;
		break;

	case TLS_state_server_key_exchange:
		ret = tls_recv_server_key_exchange(conn);
		next_state = TLS_state_certificate_request;
		break;

	// the only optional state
	case TLS_state_certificate_request:
		if(conn->verbose) {
			fprintf(stderr, "TLS_state_certificate_request\n");
		}
		ret = tls12_recv_certificate_request(conn);
		if(conn->verbose) {
			fprintf(stderr, "    ret = %d\n", ret);
		}

		if (ret == 1) conn->client_certificate_verify = 1;
		next_state = TLS_state_server_hello_done;
		break;

	case TLS_state_server_hello_done:
		if(conn->verbose) {
			fprintf(stderr, "TLS_state_server_hello_done\n");
		}
		ret = tls_recv_server_hello_done(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_client_certificate;
		else	next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_certificate:
		ret = tls_send_client_certificate(conn);
		next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_key_exchange:
		ret = tls_send_client_key_exchange(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_verify;
		else	next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_certificate_verify:
		ret = tls_send_certificate_verify(conn);
		next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_client_change_cipher_spec:
		ret = tls_send_change_cipher_spec(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tls_send_client_finished(conn);
		next_state = TLS_state_server_change_cipher_spec;
		break;

	case TLS_state_server_change_cipher_spec:
		ret = tls_recv_change_cipher_spec(conn);
		next_state = TLS_state_server_finished;
		break;

	case TLS_state_server_finished:
		ret = tls_recv_server_finished(conn);
		next_state = TLS_state_handshake_over;
		break;

	default:
		error_print();
		return -1;
	}

	if (ret < 0) {
		if (ret == TLS_ERROR_RECV_AGAIN || ret == TLS_ERROR_SEND_AGAIN) {
			return ret;
		} else {
			error_print();
			return ret;
		}
	}

	conn->handshake_state = next_state;

	// ret == 0 means this step is bypassed
	if (ret == 1) {
		tls_clean_record(conn);
	}

	return 1;
}

int tls12_do_server_handshake(TLS_CONNECT *conn)
{
	int ret;
	int next_state;

	switch (conn->handshake_state) {
	case TLS_state_client_hello:
		ret = tls_recv_client_hello(conn);
		next_state = TLS_state_server_hello;
		break;

	case TLS_state_server_hello:
		ret = tls_send_server_hello(conn);
		next_state = TLS_state_server_certificate;
		break;

	case TLS_state_server_certificate:
		ret = tls_send_server_certificate(conn);
		next_state = TLS_state_server_key_exchange;
		break;

	case TLS_state_server_key_exchange:
		ret = tls_send_server_key_exchange(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_request;
		else	next_state = TLS_state_server_hello_done;
		break;

	case TLS_state_certificate_request:
		ret = tls12_send_certificate_request(conn);
		next_state = TLS_state_server_hello_done;
		break;

	case TLS_state_server_hello_done:
		ret = tls_send_server_hello_done(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_client_certificate;
		else	next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_certificate:
		ret = tls_recv_client_certificate(conn);
		next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_key_exchange:
		ret = tls_recv_client_key_exchange(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_verify;
		else	next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_certificate_verify:
		ret = tls_recv_certificate_verify(conn);
		next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_client_change_cipher_spec:
		ret = tls_recv_change_cipher_spec(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tls_recv_client_finished(conn);
		next_state = TLS_state_server_change_cipher_spec;
		break;

	case TLS_state_server_change_cipher_spec:
		ret = tls_send_change_cipher_spec(conn);
		next_state = TLS_state_server_finished;
		break;

	case TLS_state_server_finished:
		ret = tls_send_server_finished(conn);
		next_state = TLS_state_handshake_over;
		break;

	default:
		error_print();
		return -1;
	}

	if (ret != 1) {
		if (ret == TLS_ERROR_RECV_AGAIN || ret == TLS_ERROR_SEND_AGAIN) {
			return ret;
		} else {
			error_print();
			return ret;
		}

	}

	conn->handshake_state = next_state;

	tls_clean_record(conn);

	return 1;
}


// 这个函数显然是不对的，因为这个函数就是一个重入的函数，重入函数不应该自己设置状态啊
int tls12_client_handshake(TLS_CONNECT *conn)
{
	int ret;

	while (conn->handshake_state != TLS_state_handshake_over) {

		ret = tls12_do_client_handshake(conn);

		if (ret != 1) {
			if (ret != TLS_ERROR_RECV_AGAIN && ret != TLS_ERROR_SEND_AGAIN) {
				error_print();
			}
			return ret;
		}
	}

	// TODO: cleanup conn?

	return 1;
}

int tls12_server_handshake(TLS_CONNECT *conn)
{
	int ret;


	while (conn->handshake_state != TLS_state_handshake_over) {

		ret = tls12_do_server_handshake(conn);

		if (ret != 1) {
			if (ret != TLS_ERROR_RECV_AGAIN && ret != TLS_ERROR_SEND_AGAIN) {
				error_print();
			}
			return ret;
		}
	}

	// TODO: cleanup conn?

	return 1;
}

int tls12_do_connect(TLS_CONNECT *conn)
{
	int ret;

	if (conn->handshake_state == TLS_state_handshake_over) {
		return 1;
	}

	if (conn->handshake_state == TLS_state_handshake_init) {
		conn->handshake_state = TLS_state_client_hello;
		digest_init(&conn->dgst_ctx, DIGEST_sm3());
	}

	ret = tls12_client_handshake(conn);
	if (ret == 1
		|| ret == TLS_ERROR_RECV_AGAIN
		|| ret == TLS_ERROR_SEND_AGAIN) {
		return ret;
	}
	error_print();
	return -1;
}

int tls12_do_accept(TLS_CONNECT *conn)
{
	int ret;

	if (conn->handshake_state == TLS_state_handshake_over) {
		return 1;
	}

	if (conn->handshake_state == TLS_state_handshake_init) {
		conn->handshake_state = TLS_state_client_hello;
		digest_init(&conn->dgst_ctx, DIGEST_sm3());
	}

	ret = tls12_server_handshake(conn);
	if (ret == 1
		|| ret == TLS_ERROR_RECV_AGAIN
		|| ret == TLS_ERROR_SEND_AGAIN) {
		return ret;
	}
	error_print();
	return -1;
}
