/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <unistd.h>			
#include <time.h>
#include <gmssl/tls.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>


const char *tls_record_type_name(int type)
{
	switch (type) {
	case TLS_record_change_cipher_spec: return "ChangeCipherSpec";
	case TLS_record_alert: return "Alert";
	case TLS_record_handshake: return "Handshake";
	case TLS_record_application_data: return "ApplicationData";
	}
	return NULL;
}

const char *tls_protocol_name(int protocol)
{
	switch(protocol) {
	case TLS_protocol_tlcp: return "TLCP";
	case TLS_protocol_ssl2: return "SSL2.0";
	case TLS_protocol_ssl3: return "SSL3.0";
	case TLS_protocol_tls1: return "TLS1.0";
	case TLS_protocol_tls11: return "TLS1.1";
	case TLS_protocol_tls12: return "TLS1.2";
	case TLS_protocol_tls13: return "TLS1.3";
	case TLS_protocol_dtls1: return "DTLS1.0";
	case TLS_protocol_dtls12: return "DTLS1.2";
	}
	return NULL;
}

const char *tls_cipher_suite_name(int cipher)
{
	switch (cipher) {
	case TLS_cipher_null_with_null_null: return "TLS_NULL_WITH_NULL_NULL";
	case TLS_cipher_sm4_gcm_sm3: return "TLS_SM4_GCM_SM3";
	case TLS_cipher_sm4_ccm_sm3: return "TLS_SM4_CCM_SM3";
	case TLS_cipher_ecdhe_sm4_cbc_sm3: return "TLS_ECDHE_SM4_CBC_SM3";
	case TLS_cipher_ecdhe_sm4_gcm_sm3: return "TLS_ECDHE_SM4_GCM_SM3";
	case TLS_cipher_ecc_sm4_cbc_sm3: return "TLS_ECC_SM4_CBC_SM3";
	case TLS_cipher_ecc_sm4_gcm_sm3: return "TLS_ECC_SM4_GCM_SM3";
	case TLS_cipher_ibsdh_sm4_cbc_sm3: return "TLS_IBSDH_SM4_CBC_SM3";
	case TLS_cipher_ibsdh_sm4_gcm_sm3: return "TLS_IBSDH_SM4_GCM_SM3";
	case TLS_cipher_ibc_sm4_cbc_sm3: return "TLS_IBC_SM4_CBC_SM3";
	case TLS_cipher_ibc_sm4_gcm_sm3: return "TLS_IBC_SM4_GCM_SM3";
	case TLS_cipher_rsa_sm4_cbc_sm3: return "TLS_RSA_SM4_CBC_SM3";
	case TLS_cipher_rsa_sm4_gcm_sm3: return "TLS_RSA_SM4_GCM_SM3";
	case TLS_cipher_rsa_sm4_cbc_sha256: return "TLS_RSA_SM4_CBC_SHA256";
	case TLS_cipher_rsa_sm4_gcm_sha256: return "TLS_RSA_SM4_GCM_SHA256";
	case TLS_cipher_aes_128_gcm_sha256: return "TLS_AES_128_GCM_SHA256";
	case TLS_cipher_aes_256_gcm_sha384: return "TLS_AES_256_GCM_SHA384";
	case TLS_cipher_chacha20_poly1305_sha256: return "TLS_CHACHA20_POLY1305_SHA256";
	case TLS_cipher_aes_128_ccm_sha256: return "TLS_AES_128_CCM_SHA256";
	case TLS_cipher_aes_128_ccm_8_sha256: return "TLS_AES_128_CCM_8_SHA256";
	case TLS_cipher_empty_renegotiation_info_scsv: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
	}
	return NULL;
}

const char *tls_compression_method_name(int meth)
{
	switch (meth) {
	case 0: return "no_compression";
	}
	return NULL;
}

const char *tls_extension_name(int ext)
{
	switch (ext) {
	case TLS_extension_server_name: return "server_name";
	case TLS_extension_max_fragment_length: return "max_fragment_length";
	case TLS_extension_client_certificate_url: return "client_certificate_url";
	case TLS_extension_trusted_ca_keys: return "trusted_ca_keys";
	case TLS_extension_truncated_hmac: return "truncated_hmac";
	case TLS_extension_status_request: return "status_request";
	case TLS_extension_user_mapping: return "user_mapping";
	case TLS_extension_client_authz: return "client_authz";
	case TLS_extension_server_authz: return "server_authz";
	case TLS_extension_cert_type: return "cert_type";
	case TLS_extension_supported_groups: return "supported_groups";
	case TLS_extension_ec_point_formats: return "ec_point_formats";
	case TLS_extension_srp: return "srp";
	case TLS_extension_signature_algorithms: return "signature_algorithms";
	case TLS_extension_use_srtp: return "use_srtp";
	case TLS_extension_heartbeat: return "heartbeat";
	case TLS_extension_application_layer_protocol_negotiation: return "application_layer_protocol_negotiation";
	case TLS_extension_status_request_v2: return "status_request_v2";
	case TLS_extension_signed_certificate_timestamp: return "signed_certificate_timestamp";
	case TLS_extension_client_certificate_type: return "client_certificate_type";
	case TLS_extension_server_certificate_type: return "server_certificate_type";
	case TLS_extension_padding: return "padding";
	case TLS_extension_encrypt_then_mac: return "encrypt_then_mac";
	case TLS_extension_extended_master_secret: return "extended_master_secret";
	case TLS_extension_token_binding: return "token_binding";
	case TLS_extension_cached_info: return "cached_info";
	case TLS_extension_tls_lts: return "tls_lts";
	case TLS_extension_compress_certificate: return "compress_certificate";
	case TLS_extension_record_size_limit: return "record_size_limit";
	case TLS_extension_pwd_protect: return "pwd_protect";
	case TLS_extension_pwd_clear: return "pwd_clear";
	case TLS_extension_password_salt: return "password_salt";
	case TLS_extension_ticket_pinning: return "ticket_pinning";
	case TLS_extension_tls_cert_with_extern_psk: return "tls_cert_with_extern_psk";
	case TLS_extension_delegated_credentials: return "delegated_credentials";
	case TLS_extension_session_ticket: return "session_ticket";
	case TLS_extension_TLMSP: return "TLMSP";
	case TLS_extension_TLMSP_proxying: return "TLMSP_proxying";
	case TLS_extension_TLMSP_delegate: return "TLMSP_delegate";
	case TLS_extension_supported_ekt_ciphers: return "supported_ekt_ciphers";
	case TLS_extension_pre_shared_key: return "pre_shared_key";
	case TLS_extension_early_data: return "early_data";
	case TLS_extension_supported_versions: return "supported_versions";
	case TLS_extension_cookie: return "cookie";
	case TLS_extension_psk_key_exchange_modes: return "psk_key_exchange_modes";
	case TLS_extension_certificate_authorities: return "certificate_authorities";
	case TLS_extension_oid_filters: return "oid_filters";
	case TLS_extension_post_handshake_auth: return "post_handshake_auth";
	case TLS_extension_signature_algorithms_cert: return "signature_algorithms_cert";
	case TLS_extension_key_share: return "key_share";
	case TLS_extension_transparency_info: return "transparency_info";
	case TLS_extension_connection_id: return "connection_id";
	case TLS_extension_external_id_hash: return "external_id_hash";
	case TLS_extension_external_session_id: return "external_session_id";
	case TLS_extension_quic_transport_parameters: return "quic_transport_parameters";
	case TLS_extension_ticket_request: return "ticket_request";
	case TLS_extension_renegotiation_info: return "renegotiation_info";
	};
	return NULL;
}

const char *tls_cert_type_name(int type)
{
	switch (type) {
	case TLS_cert_type_rsa_sign: return "rsa_sign";
	case TLS_cert_type_dss_sign: return "dss_sign";
	case TLS_cert_type_rsa_fixed_dh: return "rsa_fixed_dh";
	case TLS_cert_type_dss_fixed_dh: return "dss_fixed_dh";
	case TLS_cert_type_rsa_ephemeral_dh_RESERVED: return "rsa_ephemeral_dh_RESERVED";
	case TLS_cert_type_dss_ephemeral_dh_RESERVED: return "dss_ephemeral_dh_RESERVED";
	case TLS_cert_type_fortezza_dms_RESERVED: return "fortezza_dms_RESERVED";
	case TLS_cert_type_ecdsa_sign: return "ecdsa_sign";
	case TLS_cert_type_rsa_fixed_ecdh: return "rsa_fixed_ecdh_DEPRECATED";
	case TLS_cert_type_ecdsa_fixed_ecdh: return "ecdsa_fixed_ecdh_DEPRECATED";
	case TLS_cert_type_gost_sign256: return "gost_sign256";
	case TLS_cert_type_gost_sign512: return "gost_sign512";
	case TLS_cert_type_ibc_params: return "ibc_params";
	}
	return NULL;
}

const char *tls_handshake_type_name(int type)
{
	switch (type) {
	case TLS_handshake_hello_request: return "HelloRequest";
	case TLS_handshake_client_hello: return "ClientHello";
	case TLS_handshake_server_hello: return "ServerHello";
	case TLS_handshake_hello_verify_request: return "HelloVerifyRequest";
	case TLS_handshake_new_session_ticket: return "NewSessionTicket";
	case TLS_handshake_end_of_early_data: return "EndOfEarlyData";
	case TLS_handshake_hello_retry_request: return "HelloRetryRequest";
	case TLS_handshake_encrypted_extensions: return "EncryptedExtensions";
	case TLS_handshake_certificate: return "Certificate";
	case TLS_handshake_server_key_exchange: return "ServerKeyExchange";
	case TLS_handshake_certificate_request: return "CertificateRequest";
	case TLS_handshake_server_hello_done: return "ServerHelloDone";
	case TLS_handshake_certificate_verify: return "CertificateVerify";
	case TLS_handshake_client_key_exchange: return "ClientKeyExchange";
	case TLS_handshake_finished: return "Finished";
	case TLS_handshake_certificate_url: return "CertificateUrl";
	case TLS_handshake_certificate_status: return "CertificateStatus";
	case TLS_handshake_supplemental_data: return "SupplementalData";
	case TLS_handshake_key_update: return "KeyUpdate";
	case TLS_handshake_compressed_certificate: return "CompressedCertificate";
	case TLS_handshake_ekt_key: return "EktKey";
	case TLS_handshake_message_hash: return "MessageHash";
	}
	return NULL;
}

const char *tls_alert_level_name(int level)
{
	switch (level) {
	case TLS_alert_level_warning: return "warning";
	case TLS_alert_level_fatal: return "fatal";
	}
	error_print_msg("unknown alert level %d\n", level);
	return NULL;
}

const char *tls_alert_description_text(int description)
{
	switch (description) {
	case TLS_alert_close_notify: return "close_notify";
	case TLS_alert_unexpected_message: return "unexpected_message";
	case TLS_alert_bad_record_mac: return "bad_record_mac";
	case TLS_alert_decryption_failed: return "decryption_failed";
	case TLS_alert_record_overflow: return "record_overflow";
	case TLS_alert_decompression_failure: return "decompression_failure";
	case TLS_alert_handshake_failure: return "handshake_failure";
	case TLS_alert_no_certificate: return "no_certificate_RESERVED";
	case TLS_alert_bad_certificate: return "bad_certificate";
	case TLS_alert_unsupported_certificate: return "unsupported_certificate";
	case TLS_alert_certificate_revoked: return "certificate_revoked";
	case TLS_alert_certificate_expired: return "certificate_expired";
	case TLS_alert_certificate_unknown: return "certificate_unknown";
	case TLS_alert_illegal_parameter: return "illegal_parameter";
	case TLS_alert_unknown_ca: return "unknown_ca";
	case TLS_alert_access_denied: return "access_denied";
	case TLS_alert_decode_error: return "decode_error";
	case TLS_alert_decrypt_error: return "decrypt_error";
	case TLS_alert_export_restriction: return "export_restriction_RESERVED";
	case TLS_alert_protocol_version: return "protocol_version";
	case TLS_alert_insufficient_security: return "insufficient_security";
	case TLS_alert_internal_error: return "internal_error";
	case TLS_alert_user_canceled: return "user_canceled";
	case TLS_alert_no_renegotiation: return "no_renegotiation";
	case TLS_alert_unsupported_extension: return "unsupported_extension";
	case TLS_alert_unsupported_site2site: return "unsupported_site2site";
	case TLS_alert_no_area: return "no_area";
	case TLS_alert_unsupported_areatype: return "unsupported_areatype";
	case TLS_alert_bad_ibcparam: return "bad_ibcparam";
	case TLS_alert_unsupported_ibcparam: return "unsupported_ibcparam";
	case TLS_alert_identity_need: return "identity_need";
	}
	error_print_msg("unknown alert description %d", description);
	return NULL;
}

const char *tls_change_cipher_spec_text(int change_cipher_spec)
{
	switch (change_cipher_spec) {
	case TLS_change_cipher_spec: return "change_cipher_spec";
	}
	return NULL;
}

const char *tls_ec_point_format_name(int format)
{
	switch (format) {
	case TLS_point_uncompressed: return "uncompressed";
	case TLS_point_ansix962_compressed_prime: return "compressed_prime";
	case TLS_point_ansix962_compressed_char2: return "compressed_char2";
	}
	return NULL;
}

const char *tls_curve_type_name(int type)
{
	switch (type) {
	case TLS_curve_type_explicit_prime: return "explicit_prime";
	case TLS_curve_type_explicit_char2: return "explicit_char2";
	case TLS_curve_type_named_curve: return "named_curve";
	}
	return NULL;
}


// FIXME: 是否应该将函数名改为 tls_curve_name() 这样和 TLS_curve_xxx 保持一致
const char *tls_named_curve_name(int curve)
{
	switch (curve) {
	case TLS_curve_secp256k1: return "secp256k1";
	case TLS_curve_secp256r1: return "secp256r1";
	case TLS_curve_secp384r1: return "secp384r1";
	case TLS_curve_secp521r1: return "secp521r1";
	case TLS_curve_brainpoolp256r1: return "brainpoolp256r1";
	case TLS_curve_brainpoolp384r1: return "brainpoolp384r1";
	case TLS_curve_brainpoolp512r1: return "brainpoolp512r1";
	case TLS_curve_x25519: return "x25519";
	case TLS_curve_x448: return "x448";
	case TLS_curve_brainpoolp256r1tls13: return "brainpoolp256r1tls13";
	case TLS_curve_brainpoolp384r1tls13: return "brainpoolp384r1tls13";
	case TLS_curve_brainpoolp512r1tls13: return "brainpoolp512r1tls13";
	case TLS_curve_sm2p256v1: return "sm2p256v1";
	}
	return NULL;
}

const char *tls_signature_scheme_name(int scheme)
{
	switch (scheme) {
	case TLS_sig_rsa_pkcs1_sha1: return "rsa_pkcs1_sha1";
	case TLS_sig_ecdsa_sha1: return "ecdsa_sha1";
	case TLS_sig_rsa_pkcs1_sha256: return "rsa_pkcs1_sha256";
	case TLS_sig_ecdsa_secp256r1_sha256: return "ecdsa_secp256r1_sha256";
	case TLS_sig_rsa_pkcs1_sha256_legacy: return "rsa_pkcs1_sha256_legacy";
	case TLS_sig_rsa_pkcs1_sha384: return "rsa_pkcs1_sha384";
	case TLS_sig_ecdsa_secp384r1_sha384: return "ecdsa_secp384r1_sha384";
	case TLS_sig_rsa_pkcs1_sha384_legacy: return "rsa_pkcs1_sha384_legacy";
	case TLS_sig_rsa_pkcs1_sha512: return "rsa_pkcs1_sha512";
	case TLS_sig_ecdsa_secp521r1_sha512: return "ecdsa_secp521r1_sha512";
	case TLS_sig_rsa_pkcs1_sha512_legacy: return "rsa_pkcs1_sha512_legacy";
	case TLS_sig_sm2sig_sm3: return "sm2sig_sm3";
	case TLS_sig_rsa_pss_rsae_sha256: return "rsa_pss_rsae_sha256";
	case TLS_sig_rsa_pss_rsae_sha384: return "rsa_pss_rsae_sha384";
	case TLS_sig_rsa_pss_rsae_sha512: return "rsa_pss_rsae_sha512";
	case TLS_sig_ed25519: return "ed25519";
	case TLS_sig_ed448: return "ed448";
	case TLS_sig_rsa_pss_pss_sha256: return "rsa_pss_pss_sha256";
	case TLS_sig_rsa_pss_pss_sha384: return "rsa_pss_pss_sha384";
	case TLS_sig_rsa_pss_pss_sha512: return "rsa_pss_pss_sha512";
	case TLS_sig_ecdsa_brainpoolP256r1tls13_sha256: return "ecdsa_brainpoolP256r1tls13_sha256";
	case TLS_sig_ecdsa_brainpoolP384r1tls13_sha384: return "ecdsa_brainpoolP384r1tls13_sha384";
	case TLS_sig_ecdsa_brainpoolP512r1tls13_sha512: return "ecdsa_brainpoolP512r1tls13_sha512";
	}
	return NULL;
}

int tls_random_print(FILE *fp, const uint8_t random[32], int format, int indent)
{
	time_t gmt_unix_time = 0;
	const uint8_t *cp = random;
	size_t len = 4;

	tls_uint32_from_bytes((uint32_t *)&gmt_unix_time, &cp, &len);
	format_print(fp, format, indent, "Random\n");
	indent += 4;
	format_print(fp, format, indent, "gmt_unix_time : %s", ctime(&gmt_unix_time));
	format_bytes(fp, format, indent, "random", random + 4, 28);
	return 1;
}

int tls_pre_master_secret_print(FILE *fp, const uint8_t pre_master_secret[48], int format, int indent)
{
	int protocol = ((int)pre_master_secret[0] << 8) | pre_master_secret[1];
	format_print(fp, format, indent, "PreMasterSecret\n");
	indent += 4;
	format_print(fp, format, indent, "protocol : %s\n", tls_protocol_name(protocol));
	format_bytes(fp, format, indent, "pre_master_secret", pre_master_secret, 48);
	return 1;
}

// supported_versions 的格式还受到 handshake_type 影响
int tls_extension_print(FILE *fp, int type, const uint8_t *data, size_t datalen, int format, int indent)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, format, indent, "%s (%d)\n", tls_extension_name(type), type);
	indent += 4;

	switch (type) {
	case TLS_extension_supported_versions:
		if (tls_uint16array_from_bytes(&p, &len, &data, &datalen) != 1
			|| tls_length_is_zero(datalen) != 1
			|| len % 2) {
			error_print();
			return -1;
		}
		while (len) {
			uint16_t proto;
			tls_uint16_from_bytes(&proto, &p, &len);
			format_print(fp, format, indent, "%s (0x%04x)\n",
				tls_protocol_name(proto), proto);
		}
		break;
	case TLS_extension_supported_groups:
		if (tls_uint16array_from_bytes(&p, &len, &data, &datalen) != 1
			|| datalen
			|| len % 2) {
			error_print();
			return -1;
		}
		while (len) {
			uint16_t curve;
			tls_uint16_from_bytes(&curve, &p, &len);
			format_print(fp, format, indent, "%s (%d)\n",
				tls_named_curve_name(curve), curve);
		}
		break;
	case TLS_extension_ec_point_formats:
		if (tls_uint8array_from_bytes(&p, &len, &data, &datalen) != 1
			|| datalen) {
			error_print();
			return -1;
		}
		while (len) {
			uint8_t point_form;
			tls_uint8_from_bytes(&point_form, &p, &len);
			format_print(fp, format, indent, "%s (%d)\n",
				tls_ec_point_format_name(point_form), point_form);
		}
		break;
	case TLS_extension_signature_algorithms:
		if (tls_uint16array_from_bytes(&p, &len, &data, &datalen) != 1
			|| datalen
			|| len % 2) {
			error_print();
			return -1;
		}
		while (len) {
			uint16_t sig_alg;
			tls_uint16_from_bytes(&sig_alg, &p, &len);
			format_print(fp, format, indent, "%s (0x%04x)\n",
				tls_signature_scheme_name(sig_alg), sig_alg);
		}
		break;
	case TLS_extension_key_share:
		if (tls_uint16array_from_bytes(&p, &len, &data, &datalen) != 1
			|| datalen) {
			error_print();
			return -1;
		}
		while (len) {
			uint16_t group;
			const uint8_t *key_exch;
			size_t key_exch_len;

			if (tls_uint16_from_bytes(&group, &p, &len) != 1
				|| tls_uint16array_from_bytes(&key_exch, &key_exch_len, &p, &len) != 1) {
				error_print();
				return -1;
			}
			format_print(fp, format, indent, "group: %s (%d)\n", tls_named_curve_name(group), group);
			format_bytes(fp, format, indent, "key_exchange", key_exch, key_exch_len);
		}
		break;

	default:
		format_bytes(fp, format, indent, "raw_data", data, datalen);
	}
	return 1;
}

int tls13_extension_print(FILE *fp, int fmt, int ind,
	int handshake_type, int ext_type, const uint8_t *ext_data, size_t ext_datalen)
{
	switch (ext_type) {
	case TLS_extension_supported_groups:
	case TLS_extension_ec_point_formats:
	case TLS_extension_signature_algorithms:
		return tls_extension_print(fp, ext_type, ext_data, ext_datalen, fmt, ind);
	}

	format_print(fp, fmt, ind, "%s (%d)\n", tls_extension_name(ext_type), ext_type);
	ind += 4;

	switch (ext_type) {
	case TLS_extension_supported_versions:
		tls13_supported_versions_ext_print(fp, fmt, ind, handshake_type, ext_data, ext_datalen);
		break;
	case TLS_extension_key_share:
		tls13_key_share_ext_print(fp, fmt, ind, handshake_type, ext_data, ext_datalen);
		break;
	default:
		format_bytes(fp, fmt, ind, "raw_data", ext_data, ext_datalen);
	}
	return 1;
}

int tls13_extensions_print(FILE *fp, int fmt, int ind,
	int handshake_type, const uint8_t *exts, size_t extslen)
{
	uint16_t ext_type;
	const uint8_t *ext_data;
	size_t ext_datalen;

	if (!exts) {
		format_print(fp, fmt, ind, "Extensions: (null)\n");
		return 1;
	}

	format_print(fp, fmt, ind, "Extensions\n");
	ind += 4;

	while (extslen > 0) {
		if (tls_uint16_from_bytes(&ext_type, &exts, &extslen) != 1
			|| tls_uint16array_from_bytes(&ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}
		if (tls13_extension_print(fp, fmt, ind, handshake_type, ext_type, ext_data, ext_datalen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int tls_extensions_print(FILE *fp, const uint8_t *exts, size_t extslen, int format, int indent)
{
	uint16_t ext_type;
	const uint8_t *ext_data;
	size_t ext_datalen;

	format_print(fp, format, indent, "Extensions\n");
	indent += 4;
	while (extslen > 0) {
		if (tls_uint16_from_bytes(&ext_type, &exts, &extslen) != 1
			|| tls_uint16array_from_bytes(&ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}
		if (tls_extension_print(fp, ext_type, ext_data, ext_datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int tls_hello_request_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	format_print(fp, format, indent, "HelloRequest\n");
	indent += 4;
	if (data || datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_client_hello_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	int ret = -1;
	uint16_t protocol;
	const uint8_t *random;
	const uint8_t *session_id;
	const uint8_t *cipher_suites;
	const uint8_t *comp_meths;
	const uint8_t *exts;
	size_t session_id_len, cipher_suites_len, comp_meths_len, exts_len;
	size_t i;

	format_print(fp, format, indent, "ClientHello\n"); indent += 4;
	if (tls_uint16_from_bytes(&protocol, &data, &datalen) != 1) goto end;
	format_print(fp, format, indent, "Version: %s (%d.%d)\n",
		tls_protocol_name(protocol), protocol >> 8, protocol & 0xff);
	if (tls_array_from_bytes(&random, 32, &data, &datalen) != 1) goto end;
	tls_random_print(fp, random, format, indent);
	if (tls_uint8array_from_bytes(&session_id, &session_id_len, &data, &datalen) != 1) goto end;
	format_bytes(fp, format, indent, "SessionID", session_id, session_id_len);
	if (tls_uint16array_from_bytes(&cipher_suites, &cipher_suites_len, &data, &datalen) != 1) goto end;
	format_print(fp, format, indent, "CipherSuites\n");
	while (cipher_suites_len >= 2) {
		uint16_t cipher;
		if (tls_uint16_from_bytes(&cipher, &cipher_suites, &cipher_suites_len) != 1) goto end;
		format_print(fp, format, indent + 4, "%s (0x%04x)\n",
			tls_cipher_suite_name(cipher), cipher);
	}
	if (cipher_suites_len) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(&comp_meths, &comp_meths_len, &data, &datalen) != 1) goto end;
	format_print(fp, format, indent, "CompressionMethods\n");
	for (i = 0; i < comp_meths_len; i++) {
		format_print(fp, format, indent + 4, "%s (%d)\n",
			tls_compression_method_name(comp_meths[i]), comp_meths[i]);
	}
	if (datalen > 0) {
		if (tls_uint16array_from_bytes(&exts, &exts_len, &data, &datalen) != 1) goto end;
		//tls_extensions_print(fp, exts, exts_len, format, indent);
		tls13_extensions_print(fp, format, indent, TLS_handshake_client_hello, exts, exts_len);
	}
	if (datalen > 0) {
		error_print();
		return -1;
	}
	ret = 1;
end:
	return ret;
}

int tls_server_hello_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	int ret = -1;
	uint16_t protocol;
	const uint8_t *random;
	const uint8_t *session_id;
	uint16_t cipher_suite;
	uint8_t comp_meth;
	const uint8_t *exts;
	size_t session_id_len, exts_len;

	format_print(fp, format, indent, "ServerHello\n"); indent += 4;
	if (tls_uint16_from_bytes(&protocol, &data, &datalen) != 1) goto bad;
	format_print(fp, format, indent, "Version: %s (%d.%d)\n",
		tls_protocol_name(protocol), protocol >> 8, protocol & 0xff);
	if (tls_array_from_bytes(&random, 32, &data, &datalen) != 1) goto bad;
	tls_random_print(fp, random, format, indent);
	if (tls_uint8array_from_bytes(&session_id, &session_id_len, &data, &datalen) != 1) goto bad;
	format_bytes(fp, format, indent, "SessionID", session_id, session_id_len);
	if (tls_uint16_from_bytes(&cipher_suite, &data, &datalen) != 1) goto bad;
	format_print(fp, format, indent, "CipherSuite: %s (0x%04x)\n",
		tls_cipher_suite_name(cipher_suite), cipher_suite);
	if (tls_uint8_from_bytes(&comp_meth, &data, &datalen) != 1) goto bad;
	format_print(fp, format, indent, "CompressionMethod: %s (%d)\n",
		tls_compression_method_name(comp_meth), comp_meth);
	if (datalen > 0) {
		if (tls_uint16array_from_bytes(&exts, &exts_len, &data, &datalen) != 1) goto bad;
		//format_bytes(fp, format, indent, "Extensions : ", exts, exts_len); // FIXME: extensions_print		
		//tls_extensions_print(fp, exts, exts_len, format, indent);
		tls13_extensions_print(fp, format, indent, TLS_handshake_server_hello, exts, exts_len);
	}
	return 1;
bad:
	error_print();
	return -1;
}

int tls_certificate_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	const uint8_t *certs;
	size_t certslen;
	const uint8_t *der;
	size_t derlen;

	if (tls_uint24array_from_bytes(&certs, &certslen, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	while (certslen > 0) {
		if (tls_uint24array_from_bytes(&der, &derlen, &certs, &certslen) != 1) {
			error_print();
			return -1;
		}
		(void)x509_cert_print(fp, format, indent, "Certificate", der, derlen);
		(void)x509_cert_to_pem(der, derlen, fp);
	}

	if (datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_server_key_exchange_ecdhe_print(FILE *fp, const uint8_t *data, size_t datalen,
	int format, int indent)
{
	uint8_t curve_type;
	uint16_t curve;
	const uint8_t *octets;
	size_t octetslen;
	uint16_t sig_alg;
	const uint8_t *sig;
	size_t siglen;

	format_print(fp, format, indent, "ServerKeyExchange\n");
	indent += 4;
	format_print(fp, format, indent, "ServerECDHParams\n");
	format_print(fp, format, indent + 4, "curve_params\n");
	if (tls_uint8_from_bytes(&curve_type, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, format, indent + 8, "curve_type: %s (%d)\n",
		tls_curve_type_name(curve_type), curve_type);
	if (tls_uint16_from_bytes(&curve, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, format, indent + 8, "named_curve: %s (%d)\n",
		tls_named_curve_name(curve), curve);
	if (tls_uint8array_from_bytes(&octets, &octetslen, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, format, indent + 4, "point", octets, octetslen);
	if (tls_uint16_from_bytes(&sig_alg, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, format, indent, "SignatureScheme: %s (0x%04x)\n",
		tls_signature_scheme_name(sig_alg), sig_alg);
	if (tls_uint16array_from_bytes(&sig, &siglen, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, format, indent, "Siganture", sig, siglen);
	if (datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_server_key_exchange_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	int cipher_suite = (format >> 8) & 0xffff;

	switch (cipher_suite) {
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecc_sm4_gcm_sm3:
		if (tlcp_server_key_exchange_pke_print(fp, data, datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
		if (tls_server_key_exchange_ecdhe_print(fp, data, datalen, format, indent) != 1) {
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

int tls_certificate_subjects_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *a;
	size_t alen;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	while (dlen) {
		const uint8_t *name;
		size_t namelen;

		if (tls_uint16array_from_bytes(&a, &alen, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (asn1_sequence_from_der(&name, &namelen, &a, &alen) != 1
			|| asn1_length_is_zero(alen) != 1) {
			error_print();
			return -1;
		}
		x509_name_print(fp, fmt, ind, "DistinguishedName", name, namelen);
	}
	return 1;
}

int tls_certificate_request_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	const uint8_t *cert_types;
	const uint8_t *ca_names;
	size_t cert_types_len, ca_names_len;

	format_print(fp, format, indent, "CertificateRequest\n"); indent += 4;
	if (tls_uint8array_from_bytes(&cert_types, &cert_types_len, &data, &datalen) != 1) goto bad;
	format_print(fp, format, indent, "cert_types\n");
	while (cert_types_len--) {
		int cert_type = *cert_types++;
		format_print(fp, format, indent + 4, "%s (%d)\n", tls_cert_type_name(cert_type), cert_type);
	}
	if (tls_uint16array_from_bytes(&ca_names, &ca_names_len, &data, &datalen) != 1) goto bad;
	tls_certificate_subjects_print(fp, format, indent, "CAnames", ca_names, ca_names_len);

	return 1;
bad:
	error_print();
	return -1;
}

int tls_server_hello_done_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	if (datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_client_key_exchange_pke_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	const uint8_t *enced_pms;
	size_t enced_pms_len;

	if (tls_uint16array_from_bytes(&enced_pms, &enced_pms_len, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, format, indent, "EncryptedPreMasterSecret", enced_pms, enced_pms_len);
	return 1;
}

int tls_client_key_exchange_ecdhe_print(FILE *fp, const uint8_t *data, size_t datalen,
	int format, int indent)
{
	const uint8_t *octets;
	size_t octetslen;

	format_print(fp, format, indent, "ClientKeyExchange\n");
	indent += 4;
	if (tls_uint8array_from_bytes(&octets, &octetslen, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, format, indent, "ecdh_Yc", octets, octetslen);
	if (datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_client_key_exchange_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	int cipher_suite = (format >> 8) & 0xffff;
	switch (cipher_suite) {
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecc_sm4_gcm_sm3:
		if (tls_client_key_exchange_pke_print(fp, data, datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
		if (tls_client_key_exchange_ecdhe_print(fp, data, datalen, format, indent) != 1) {
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

int tls_certificate_verify_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	format_print(fp, format, indent, "CertificateVerify\n");
	format_bytes(fp, format, indent + 4, "Signature", data, datalen);
	return 1;
}

int tls_finished_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	format_print(fp, format, indent, "Finished\n");
	indent += 4;
	format_bytes(fp, format, indent, "verify_data", data, datalen);
	return 1;
}

int tls13_handshake_print(FILE *fp, int fmt, int ind, const uint8_t *handshake, size_t handshake_len)
{
	const uint8_t *p = handshake;
	size_t len = handshake_len;
	uint8_t type;
	const uint8_t *data;
	size_t datalen;

	if (tls_uint8_from_bytes(&type, &handshake, &handshake_len) != 1
		|| tls_uint24array_from_bytes(&data, &datalen, &handshake, &handshake_len) != 1
		|| tls_length_is_zero(handshake_len) != 1) {
		error_print();
		return -1;
	}

	switch (type) {
	case TLS_handshake_certificate:
	case TLS_handshake_certificate_request:
	case TLS_handshake_certificate_verify:
		format_print(fp, fmt, ind, "Handshake\n");
		ind += 4;
		format_print(fp, fmt, ind, "Type: %s (%d)\n", tls_handshake_type_name(type), type);
		format_print(fp, fmt, ind, "Length: %zu\n", datalen);
		break;
	}
	switch (type) {
	case TLS_handshake_certificate:
		return tls13_certificate_print(fp, fmt, ind, data, datalen);
	case TLS_handshake_certificate_request:
		return tls13_certificate_request_print(fp, fmt, ind, data, datalen);
	case TLS_handshake_certificate_verify:
		return tls13_certificate_verify_print(fp, fmt, ind, data, datalen);
	}

	return tls_handshake_print(fp, p, len, fmt, ind);
}

// 这个是有问题的，因为TLS 1.3的证书和TLS 1.2是不一样的
int tls_handshake_print(FILE *fp, const uint8_t *handshake, size_t handshakelen, int format, int indent)
{
	const uint8_t *cp = handshake;
	uint8_t type;
	const uint8_t *data;
	uint24_t datalen;

	format_print(fp, format, indent, "Handshake\n");
	indent += 4;

	if (tls_uint8_from_bytes(&type, &cp, &handshakelen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, format, indent, "Type: %s (%d)\n", tls_handshake_type_name(type), type);
	if (tls_uint24_from_bytes(&datalen, &cp, &handshakelen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, format, indent, "Length: %zu\n", datalen);

	if (tls_array_from_bytes(&data, datalen, &cp, &handshakelen) != 1) {
		error_print();
		return -1;
	}
	switch (type) {
	case TLS_handshake_hello_request:
		if (tls_hello_request_print(fp, data, datalen, format, indent) != 1)
			{ error_print(); return -1; } break;
	case TLS_handshake_client_hello:
		if (tls_client_hello_print(fp, data, datalen, format, indent) != 1)
			{ error_print(); return -1; } break;
	case TLS_handshake_server_hello:
		if (tls_server_hello_print(fp, data, datalen, format, indent) != 1)
			{ error_print(); return -1; } break;
	case TLS_handshake_encrypted_extensions:
		tls13_encrypted_extensions_print(fp, format, indent, data, datalen);
		break;

	case TLS_handshake_certificate:
		if (tls_certificate_print(fp, data, datalen, format, indent) != 1)
			{ error_print(); return -1; } break;
	case TLS_handshake_server_key_exchange:
		if (tls_server_key_exchange_print(fp, data, datalen, format, indent) != 1)
			{ error_print(); return -1; } break;
	case TLS_handshake_certificate_request:
		if (tls_certificate_request_print(fp, data, datalen, format, indent) != 1)
			{ error_print(); return -1; } break;
	case TLS_handshake_server_hello_done:
		if (tls_server_hello_done_print(fp, data, datalen, format, indent) != 1)
			{ error_print(); return -1; } break;
	case TLS_handshake_client_key_exchange:
		if (tls_client_key_exchange_print(fp, data, datalen, format, indent) != 1)
			{ error_print(); return -1; } break;
	case TLS_handshake_certificate_verify:
		if (tls_certificate_verify_print(fp, data, datalen, format, indent) != 1)
			{ error_print(); return -1; } break;
	case TLS_handshake_finished:
		if (tls_finished_print(fp, data, datalen, format, indent) != 1)
			{ error_print(); return -1; } break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int tls_alert_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	if (datalen != 2) {
		error_print();
		return -1;
	}
	format_print(fp, format, indent, "Alert:\n");
	indent += 4;
	format_print(fp, format, indent, "Level: %s (%d)\n", tls_alert_level_name(data[0]), data[0]);
	format_print(fp, format, indent, "Reason: %s (%d)\n", tls_alert_description_text(data[1]), data[1]);
	return 1;
}

int tls_change_cipher_spec_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	if (datalen != 1) {
		error_print();
		return -1;
	}
	format_print(fp, format, indent, "ChangeCipherSpec\n");
	indent += 4;
	format_print(fp, format, indent, "type : %s (%d)\n", tls_change_cipher_spec_text(data[0]), data[0]);
	return 1;
}

int tls_application_data_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	format_bytes(fp, format, indent, "ApplicationData", data, datalen);
	return 1;
}

int tls13_record_print(FILE *fp, int format, int indent, const uint8_t *record, size_t recordlen)
{
	const uint8_t *data;
	size_t datalen;
	int protocol;

	format |= TLS_cipher_sm4_gcm_sm3 << 8;

	if (!fp || !record || recordlen < 5) {
		error_print();
		return -1;
	}
	protocol = tls_record_protocol(record);
	format_print(fp, format, indent, "Record\n"); indent += 4;
	format_print(fp, format, indent, "ContentType: %s (%d)\n", tls_record_type_name(record[0]), record[0]);
	format_print(fp, format, indent, "Version: %s (%d.%d)\n", tls_protocol_name(protocol), protocol >> 8, protocol & 0xff);
	format_print(fp, format, indent, "Length: %d\n", tls_record_data_length(record));

	data = tls_record_data(record);
	datalen = tls_record_data_length(record);

	if (recordlen < tls_record_length(record)) {
		error_print();
		return -1;
	}

	// 最高字节设置后强制打印记录原始数据
	if (format >> 24) {
		format_bytes(fp, format, indent, "Data", data, datalen);
		fprintf(fp, "\n");
		return 1;
	}

	switch (record[0]) {
	case TLS_record_handshake:
		tls13_handshake_print(fp, format, indent, data, datalen);
		break;
	case TLS_record_alert:
		if (tls_alert_print(fp, data, datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_record_change_cipher_spec:
		if (tls_change_cipher_spec_print(fp, data, datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_record_application_data:
		if (tls_application_data_print(fp, data, datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	recordlen -= tls_record_length(record);
	if (recordlen) {
		format_print(fp, 0, 0, "DataLeftInRecord: %zu\n", recordlen);
	}

	fprintf(fp, "\n");
	return 1;

}


// 仅从record数据是不能判断这个record是TLS 1.2还是TLS 1.3
// 不同协议上，同名的握手消息，其格式也是不一样的。这真是太恶心了！！！！

// 当消息为ClientKeyExchange,ServerKeyExchange，需要密码套件中的密钥交换算法信息
// 当消息为加密的Finished，记录类型为Handshake，但是记录负载数据中没有Handshake头
// 注意：这里的recordlen 是冗余的，要容忍recordlen的错误
//
// supported_versions 的格式由handshake_type 是否为ClientHello, ServerHello 决定
// record中是包含这个信息的，但是在exts中没有这个信息
int tls_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent)
{
	const uint8_t *data;
	size_t datalen;
	int protocol;

	if (!fp || !record || recordlen < 5) {
		error_print();
		return -1;
	}
	protocol = tls_record_protocol(record);
	format_print(fp, format, indent, "Record\n"); indent += 4;
	format_print(fp, format, indent, "ContentType: %s (%d)\n", tls_record_type_name(record[0]), record[0]);
	format_print(fp, format, indent, "Version: %s (%d.%d)\n", tls_protocol_name(protocol), protocol >> 8, protocol & 0xff);
	format_print(fp, format, indent, "Length: %d\n", tls_record_data_length(record));

	data = tls_record_data(record);
	datalen = tls_record_data_length(record);

	if (recordlen < tls_record_length(record)) {
		error_print();
		return -1;
	}

	// 最高字节设置后强制打印记录原始数据
	if (format >> 24) {
		format_bytes(fp, format, indent, "Data", data, datalen);
		fprintf(fp, "\n");
		return 1;
	}

	switch (record[0]) {
	case TLS_record_handshake:
		if (tls_handshake_print(fp, data, datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_record_alert:
		if (tls_alert_print(fp, data, datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_record_change_cipher_spec:
		if (tls_change_cipher_spec_print(fp, data, datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_record_application_data:
		if (tls_application_data_print(fp, data, datalen, format, indent) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	recordlen -= tls_record_length(record);
	if (recordlen) {
		format_print(fp, 0, 0, "DataLeftInRecord: %zu\n", recordlen);
	}

	fprintf(fp, "\n");
	return 1;




























}

int tls_secrets_print(FILE *fp,
	const uint8_t *pre_master_secret, size_t pre_master_secret_len,
	const uint8_t client_random[32], const uint8_t server_random[32],
	const uint8_t master_secret[48],
	const uint8_t *key_block, size_t key_block_len,
	int format, int indent)
{
	// 应该检查一下key_block_len的值，判断是否支持，或者算法选择, 或者要求输入一个cipher_suite参数
	format_bytes(stderr, format, indent, "pre_master_secret", pre_master_secret, pre_master_secret_len);
	format_bytes(stderr, format, indent, "client_random", client_random, 32);
	format_bytes(stderr, format, indent, "server_random", server_random, 32);
	format_bytes(stderr, format, indent, "master_secret", master_secret, 48);
	format_bytes(stderr, format, indent, "client_write_mac_key", key_block, 32);
	format_bytes(stderr, format, indent, "server_write_mac_key", key_block + 32, 32);
	format_bytes(stderr, format, indent, "client_write_enc_key", key_block + 64, 16);
	format_bytes(stderr, format, indent, "server_write_enc_key", key_block + 80, 16);
	format_print(stderr, format, indent, "\n");
	return 1;
}
