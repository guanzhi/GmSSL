/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_TLS_H
#define GMSSL_TLS_H


#include <stdint.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/digest.h>
#include <gmssl/block_cipher.h>
#include <gmssl/socket.h>
#include <gmssl/x509_key.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef uint32_t uint24_t;

#define tls_uint8_size()	1
#define tls_uint16_size()	2
#define tls_uint24_size()	3

void tls_uint8_to_bytes(uint8_t a, uint8_t **out, size_t *outlen);
void tls_uint16_to_bytes(uint16_t a, uint8_t **out, size_t *outlen);
void tls_uint24_to_bytes(uint24_t a, uint8_t **out, size_t *outlen);
void tls_uint32_to_bytes(uint32_t a, uint8_t **out, size_t *outlen);
void tls_uint64_to_bytes(uint64_t a, uint8_t **out, size_t *outlen);
void tls_array_to_bytes(const uint8_t *data, size_t len, uint8_t **out, size_t *outlen);
void tls_uint8array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
void tls_uint16array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
void tls_uint24array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
int tls_uint8_from_bytes(uint8_t *a, const uint8_t **in, size_t *inlen);
int tls_uint16_from_bytes(uint16_t *a, const uint8_t **in, size_t *inlen);
int tls_uint24_from_bytes(uint24_t *a, const uint8_t **in, size_t *inlen);
int tls_uint32_from_bytes(uint32_t *a, const uint8_t **in, size_t *inlen);
int tls_uint64_from_bytes(uint64_t *a, const uint8_t **in, size_t *inlen);
int tls_array_from_bytes(const uint8_t **data, size_t datalen, const uint8_t **in, size_t *inlen);
int tls_uint8array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_uint16array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_uint24array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_length_is_zero(size_t len);
int tls_uint16array_from_file(uint8_t *arr, size_t *arrlen, size_t maxlen, FILE *fp);


int tls_type_is_in_list(int cipher, const int *list, size_t list_count);


// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

typedef enum {
	TLS_protocol_tlcp			= 0x0101,
	TLS_protocol_ssl2			= 0x0002,
	TLS_protocol_ssl3			= 0x0300,
	TLS_protocol_tls1			= 0x0301,
	TLS_protocol_tls11			= 0x0302,
	TLS_protocol_tls12			= 0x0303,
	TLS_protocol_tls13			= 0x0304,
	TLS_protocol_dtls1			= 0xfeff, // {254, 255}
	TLS_protocol_dtls12			= 0xfefd, // {254, 253}
} TLS_PROTOCOL;

const char *tls_protocol_name(int proto);
int tls_protocol_from_name(const char *name);

typedef enum {
	TLS_cipher_null_with_null_null		= 0x0000,

	// TLS 1.3, RFC 8998
	TLS_cipher_sm4_gcm_sm3			= 0x00c6,
	TLS_cipher_sm4_ccm_sm3			= 0x00c7,

	// TLCP, GB/T 38636-2020, GM/T 0024-2012
	TLS_cipher_ecdhe_sm4_cbc_sm3		= 0xe011, // TODO: let TLSv1.2 use this as default cipher suite
	TLS_cipher_ecdhe_sm4_gcm_sm3		= 0xe051,
	TLS_cipher_ecc_sm4_cbc_sm3		= 0xe013,
	TLS_cipher_ecc_sm4_gcm_sm3		= 0xe053,
	TLS_cipher_ibsdh_sm4_cbc_sm3		= 0xe015,
	TLS_cipher_ibsdh_sm4_gcm_sm3		= 0xe055,
	TLS_cipher_ibc_sm4_cbc_sm3		= 0xe017,
	TLS_cipher_ibc_sm4_gcm_sm3		= 0xe057,
	TLS_cipher_rsa_sm4_cbc_sm3		= 0xe019,
	TLS_cipher_rsa_sm4_gcm_sm3		= 0xe059,
	TLS_cipher_rsa_sm4_cbc_sha256		= 0xe01c,
	TLS_cipher_rsa_sm4_gcm_sha256		= 0xe05a,

	// TLS 1.3 RFC 8446
	TLS_cipher_aes_128_gcm_sha256		= 0x1301, // Mandatory-to-implement
	TLS_cipher_aes_256_gcm_sha384		= 0x1302, // SHOULD implement
	TLS_cipher_chacha20_poly1305_sha256	= 0x1303, // SHOULD implement
	TLS_cipher_aes_128_ccm_sha256		= 0x1304,
	TLS_cipher_aes_128_ccm_8_sha256		= 0x1305,

	TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256 = 0xc023,

	TLS_cipher_empty_renegotiation_info_scsv = 0x00ff,
} TLS_CIPHER_SUITE;

const char *tls_cipher_suite_name(int cipher);
int tls_cipher_suite_from_name(const char *name);
int tls_cipher_suites_select(const uint8_t *client_ciphers, size_t client_ciphers_len,
	const int *server_ciphers, size_t server_ciphers_cnt, int *selected_cipher);


typedef enum {
	TLS_compression_null	= 0,
	TLS_compression_default	= 1,
} TLS_COMPRESSION_METHOD;

const char *tls_compression_method_name(int meth);


typedef enum {
	TLS_record_invalid			= 0,  // TLS 1.3
	TLS_record_change_cipher_spec		= 20, // 0x14
	TLS_record_alert			= 21, // 0x15
	TLS_record_handshake			= 22, // 0x16
	TLS_record_application_data		= 23, // 0x17
	TLS_record_heartbeat			= 24, // 0x18
	TLS_record_tls12_cid			= 25, // 0x19
} TLS_RECORD_TYPE;

const char *tls_record_type_name(int type);


typedef enum  {
	TLS_handshake_hello_request		= 0,
	TLS_handshake_client_hello		= 1,
	TLS_handshake_server_hello		= 2,
	TLS_handshake_hello_verify_request	= 3,
	TLS_handshake_new_session_ticket	= 4,
	TLS_handshake_end_of_early_data		= 5,
	TLS_handshake_hello_retry_request	= 6,
	TLS_handshake_encrypted_extensions	= 8,
	TLS_handshake_certificate		= 11,
	TLS_handshake_server_key_exchange	= 12,
	TLS_handshake_certificate_request	= 13,
	TLS_handshake_server_hello_done		= 14,
	TLS_handshake_certificate_verify	= 15,
	TLS_handshake_client_key_exchange	= 16,
	TLS_handshake_finished			= 20,
	TLS_handshake_certificate_url		= 21,
	TLS_handshake_certificate_status	= 22,
	TLS_handshake_supplemental_data		= 23,
	TLS_handshake_key_update		= 24,
	TLS_handshake_compressed_certificate	= 25,
	TLS_handshake_ekt_key			= 26,
	TLS_handshake_message_hash		= 254,
} TLS_HANDSHAKE_TYPE;

const char *tls_handshake_type_name(int type);


typedef enum {
	TLS_cert_type_rsa_sign			= 1,
	TLS_cert_type_dss_sign			= 2,
	TLS_cert_type_rsa_fixed_dh		= 3,
	TLS_cert_type_dss_fixed_dh		= 4,
	TLS_cert_type_rsa_ephemeral_dh_RESERVED = 5,
	TLS_cert_type_dss_ephemeral_dh_RESERVED = 6,
	TLS_cert_type_fortezza_dms_RESERVED	= 20,
	TLS_cert_type_ecdsa_sign		= 64, // also for sm2
	TLS_cert_type_rsa_fixed_ecdh		= 65,
	TLS_cert_type_ecdsa_fixed_ecdh		= 66,
	TLS_cert_type_gost_sign256		= 67,
	TLS_cert_type_gost_sign512		= 68,
	TLS_cert_type_ibc_params		= 80,
} TLS_CERTIFICATE_TYPE;

const char *tls_cert_type_name(int type);
int tls_cert_type_from_oid(int oid);

typedef enum {
	TLS_extension_server_name		= 0,
	TLS_extension_max_fragment_length	= 1,
	TLS_extension_client_certificate_url	= 2,
	TLS_extension_trusted_ca_keys		= 3,
	TLS_extension_truncated_hmac		= 4,
	TLS_extension_status_request		= 5,
	TLS_extension_user_mapping		= 6,
	TLS_extension_client_authz		= 7,
	TLS_extension_server_authz		= 8,
	TLS_extension_cert_type			= 9,
	TLS_extension_supported_groups		= 10,
	TLS_extension_ec_point_formats		= 11,
	TLS_extension_srp			= 12,
	TLS_extension_signature_algorithms	= 13,
	TLS_extension_use_srtp			= 14,
	TLS_extension_heartbeat			= 15,
	TLS_extension_application_layer_protocol_negotiation= 16,
	TLS_extension_status_request_v2		= 17,
	TLS_extension_signed_certificate_timestamp = 18,
	TLS_extension_client_certificate_type	= 19,
	TLS_extension_server_certificate_type	= 20,
	TLS_extension_padding			= 21,
	TLS_extension_encrypt_then_mac		= 22,
	TLS_extension_extended_master_secret	= 23,
	TLS_extension_token_binding		= 24,
	TLS_extension_cached_info		= 25,
	TLS_extension_tls_lts			= 26,
	TLS_extension_compress_certificate	= 27,
	TLS_extension_record_size_limit		= 28,
	TLS_extension_pwd_protect		= 29,
	TLS_extension_pwd_clear			= 30,
	TLS_extension_password_salt		= 31,
	TLS_extension_ticket_pinning		= 32,
	TLS_extension_tls_cert_with_extern_psk	= 33,
	TLS_extension_delegated_credentials	= 34,
	TLS_extension_session_ticket		= 35,
	TLS_extension_TLMSP			= 36,
	TLS_extension_TLMSP_proxying		= 37,
	TLS_extension_TLMSP_delegate		= 38,
	TLS_extension_supported_ekt_ciphers	= 39,
	TLS_extension_pre_shared_key		= 41,
	TLS_extension_early_data		= 42,
	TLS_extension_supported_versions	= 43,
	TLS_extension_cookie			= 44,
	TLS_extension_psk_key_exchange_modes	= 46,
	TLS_extension_certificate_authorities	= 47,
	TLS_extension_oid_filters		= 48,
	TLS_extension_post_handshake_auth	= 49,
	TLS_extension_signature_algorithms_cert	= 50,
	TLS_extension_key_share			= 51,
	TLS_extension_transparency_info		= 52,
	TLS_extension_connection_id		= 53,
	TLS_extension_external_id_hash		= 55,
	TLS_extension_external_session_id	= 56,
	TLS_extension_quic_transport_parameters	= 57,
	TLS_extension_ticket_request		= 58,
	TLS_extension_renegotiation_info	= 65281,
} TLS_EXTENSION_TYPE;

const char *tls_extension_name(int ext);


typedef enum {
	TLS_point_uncompressed			= 0,
	TLS_point_ansix962_compressed_prime	= 1,
	TLS_point_ansix962_compressed_char2	= 2,
} TLS_EC_POINT_FORMAT;

const char *tls_ec_point_format_name(int format);


typedef enum {
	TLS_curve_type_explicit_prime		= 1,
	TLS_curve_type_explicit_char2		= 2,
	TLS_curve_type_named_curve		= 3,
} TLS_CURVE_TYPE;

const char *tls_curve_type_name(int type);
int tls_named_curve_from_name(const char *name);

typedef enum {
	TLS_curve_secp256k1			= 22,
	TLS_curve_secp256r1			= 23,
	TLS_curve_secp384r1			= 24,
	TLS_curve_secp521r1			= 25,
	TLS_curve_brainpoolp256r1		= 26,
	TLS_curve_brainpoolp384r1		= 27,
	TLS_curve_brainpoolp512r1		= 28,
	TLS_curve_x25519			= 29,
	TLS_curve_x448				= 30,
	TLS_curve_brainpoolp256r1tls13		= 31,
	TLS_curve_brainpoolp384r1tls13		= 32,
	TLS_curve_brainpoolp512r1tls13		= 33,
	TLS_curve_sm2p256v1			= 41, // GmSSLv2: 30
} TLS_NAMED_CURVE;

const char *tls_named_curve_name(int named_curve);
int tls_named_curve_oid(int named_curve);
int tls_named_curve_from_oid(int oid);

typedef enum {
	TLS_sig_rsa_pkcs1_sha1			= 0x0201,
	TLS_sig_ecdsa_sha1			= 0x0203,
	TLS_sig_rsa_pkcs1_sha256		= 0x0401,
	TLS_sig_ecdsa_secp256r1_sha256		= 0x0403,
	TLS_sig_rsa_pkcs1_sha256_legacy		= 0x0420,
	TLS_sig_rsa_pkcs1_sha384		= 0x0501,
	TLS_sig_ecdsa_secp384r1_sha384		= 0x0503,
	TLS_sig_rsa_pkcs1_sha384_legacy		= 0x0520,
	TLS_sig_rsa_pkcs1_sha512		= 0x0601,
	TLS_sig_ecdsa_secp521r1_sha512		= 0x0603,
	TLS_sig_rsa_pkcs1_sha512_legacy		= 0x0620,
	TLS_sig_sm2sig_sm3			= 0x0708,
	TLS_sig_rsa_pss_rsae_sha256		= 0x0804,
	TLS_sig_rsa_pss_rsae_sha384		= 0x0805,
	TLS_sig_rsa_pss_rsae_sha512		= 0x0806,
	TLS_sig_ed25519				= 0x0807,
	TLS_sig_ed448				= 0x0808,
	TLS_sig_rsa_pss_pss_sha256		= 0x0809,
	TLS_sig_rsa_pss_pss_sha384		= 0x080A,
	TLS_sig_rsa_pss_pss_sha512		= 0x080B,
	TLS_sig_ecdsa_brainpoolP256r1tls13_sha256 = 0x081A,
	TLS_sig_ecdsa_brainpoolP384r1tls13_sha384 = 0x081B,
	TLS_sig_ecdsa_brainpoolP512r1tls13_sha512 = 0x081C,
} TLS_SIGNATURE_SCHEME;

const char *tls_signature_scheme_name(int scheme);
int tls_signature_scheme_from_name(const char *name);
int tls_signature_scheme_from_algorithm_and_group_oid(int alg_oid, int group_oid);

int tls_signature_scheme_group_oid(int sig_alg); // return OID_sm2, OID_prime256v1(OID_secp256r1), OID_undef
int tls_signature_scheme_algorithm_oid(int sig_alg); // return OID_sm2sign_with_sm3, OID_ecdsa_with_sha256, OID_undef





// in tls12/tlcp, relation of sig_alg and cipher is decided by cipher_suite
// in tls13, no restriction (implementation can check)
int tls_signature_scheme_match_cipher_suite(int sig_alg, int cipher_suite); // only called in tls12


typedef enum {
	TLS_change_cipher_spec = 1,
} TLS_CHANGE_CIPHER_SPEC_TYPE;


typedef enum {
	TLS_alert_level_undefined = 0,
	TLS_alert_level_warning = 1,
	TLS_alert_level_fatal = 2,
} TLS_ALERT_LEVEL;

const char *tls_alert_level_name(int level);


typedef enum {
	TLS_alert_close_notify			= 0,
	TLS_alert_unexpected_message		= 10,
	TLS_alert_bad_record_mac		= 20,
	TLS_alert_decryption_failed		= 21,
	TLS_alert_record_overflow		= 22,
	TLS_alert_decompression_failure		= 30,
	TLS_alert_handshake_failure		= 40,
	TLS_alert_no_certificate		= 41,
	TLS_alert_bad_certificate		= 42,
	TLS_alert_unsupported_certificate	= 43,
	TLS_alert_certificate_revoked		= 44,
	TLS_alert_certificate_expired		= 45,
	TLS_alert_certificate_unknown		= 46,
	TLS_alert_illegal_parameter		= 47,
	TLS_alert_unknown_ca			= 48,
	TLS_alert_access_denied			= 49,
	TLS_alert_decode_error			= 50,
	TLS_alert_decrypt_error			= 51,
	TLS_alert_export_restriction		= 60,
	TLS_alert_protocol_version		= 70,
	TLS_alert_insufficient_security		= 71,
	TLS_alert_internal_error		= 80,
	TLS_alert_user_canceled			= 90,
	TLS_alert_no_renegotiation		= 100,
	TLS_alert_missing_extension		= 109,
	TLS_alert_unsupported_extension		= 110,
	TLS_alert_certificate_unobtainable	= 111,
	TLS_alert_unsupported_site2site		= 200,
	TLS_alert_no_area			= 201,
	TLS_alert_unsupported_areatype		= 202,
	TLS_alert_bad_ibcparam			= 203,
	TLS_alert_unsupported_ibcparam		= 204,
	TLS_alert_identity_need			= 205,
} TLS_ALERT_DESCRIPTION;

const char *tls_alert_description_text(int description);


// Key and Crypto

int tls_prf(const uint8_t *secret, size_t secretlen, const char *label,
	const uint8_t *seed, size_t seedlen,
	const uint8_t *more, size_t morelen,
	size_t outlen, uint8_t *out);

int tls_cbc_encrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *enc_key,
	const uint8_t seq_num[8], const uint8_t header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int tls_cbc_decrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *dec_key,
	const uint8_t seq_num[8], const uint8_t header[5],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int tls_record_encrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *cbc_key,
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);
int tls_record_decrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *cbc_key,
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

int tls_seq_num_incr(uint8_t seq_num[8]);
void tls_seq_num_reset(uint8_t seq_num[8]);

int tls_random_generate(uint8_t random[32]);
int tls_random_print(FILE *fp, const uint8_t random[32], int format, int indent);
int tls_pre_master_secret_generate(uint8_t pre_master_secret[48], int protocol);
int tls_pre_master_secret_print(FILE *fp, const uint8_t pre_master_secret[48], int format, int indent);

int tls_secrets_print(FILE *fp,
	const uint8_t *pre_master_secret, size_t pre_master_secret_len,
	const uint8_t client_random[32], const uint8_t server_random[32],
	const uint8_t master_secret[48],
	const uint8_t *key_block, size_t key_block_len,
	int format, int indent);


int tls13_hkdf_extract(const DIGEST *digest, const uint8_t salt[32], const uint8_t in[32], uint8_t out[32]);
int tls13_hkdf_expand_label(const DIGEST *digest, const uint8_t secret[32],
	const char *label, const uint8_t *context, size_t context_len,
	size_t outlen, uint8_t *out);
int tls13_derive_secret(const uint8_t secret[32], const char *label, const DIGEST_CTX *dgst_ctx, uint8_t out[32]);





// Record Layer

typedef struct {
	uint8_t type;
	uint8_t protocol[2];
	uint8_t data_length[2];
} TLS_RECORD_HEADER;

#define TLS_RECORD_HEADER_SIZE		(1 + tls_uint16_size() + tls_uint16_size())		// 5
#define TLS_MAX_PLAINTEXT_SIZE		(1 << 14)						// 16384
#define TLS_MAX_COMPRESSED_SIZE		((1 << 14) + 1024)					// 17408
#define TLS_MAX_CIPHERTEXT_SIZE		((1 << 14) + 2048)					// 18432
#define TLS_MAX_RECORD_SIZE		(TLS_RECORD_HEADER_SIZE + TLS_MAX_CIPHERTEXT_SIZE)	// 18437

#define tls_record_type(record)		((record)[0])
#define tls_record_header(record)	((record)+0)
#define tls_record_protocol(record)	(((uint16_t)((record)[1]) << 8) | (record)[2])
#define tls_record_data(record)		((record)+TLS_RECORD_HEADER_SIZE)
#define tls_record_data_length(record)	(((uint16_t)((record)[3]) << 8) | (record)[4])
#define tls_record_length(record)	((size_t)(TLS_RECORD_HEADER_SIZE + tls_record_data_length(record)))

int tls_record_set_type(uint8_t *record, int type);
int tls_record_set_protocol(uint8_t *record, int protocol);
int tls_record_set_data_length(uint8_t *record, size_t length);
int tls_record_set_data(uint8_t *record, const uint8_t *data, size_t datalen);


// parse ServerKeyExchange, ClientKeyExchange depends on current cipher_suite		
#define tls_format_set_cipher_suite(fmt,cipher)	do {(fmt)|=((cipher)<<8);} while (0)
int tls_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent);
int tlcp_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent);

int tls_record_send(const uint8_t *record, size_t recordlen, tls_socket_t sock);
int tls_record_recv(uint8_t *record, size_t *recordlen, tls_socket_t sock);
int tls12_record_recv(uint8_t *record, size_t *recordlen, tls_socket_t sock);



// Handshake
typedef struct {
	uint8_t type;
	uint8_t length[3];
} TLS_HANDSHAKE_HEADER;

#define TLS_HANDSHAKE_HEADER_SIZE	4
#define TLS_MAX_HANDSHAKE_DATA_SIZE 	(TLS_MAX_PLAINTEXT_SIZE - TLS_HANDSHAKE_HEADER_SIZE)

#define tls_handshake_data(p)		((p) + TLS_HANDSHAKE_HEADER_SIZE)
//#define tls_handshake_data_length(p)


int tls_record_set_handshake_header(uint8_t *record, size_t *recordlen,
	int type, int length);
int tls_record_set_handshake(uint8_t *record, size_t *recordlen,
	int type, const uint8_t *data, size_t datalen);
int tls_record_get_handshake(const uint8_t *record,
	int *type, const uint8_t **data, size_t *datalen);
int tls_handshake_print(FILE *fp, const uint8_t *handshake, size_t handshakelen, int format, int indent);


// Alert
typedef struct {
	uint8_t level;
	uint8_t description;
} TLS_ALERT;

#define TLS_ALERT_RECORD_SIZE (TLS_RECORD_HEADER_SIZE + 2)

int tls_record_set_alert(uint8_t *record, size_t *recordlen, int alert_level, int alert_description);
int tls_record_get_alert(const uint8_t *record, int *alert_level, int *alert_description);
int tls_alert_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);


// ChangeCipherSpec

typedef struct {
	uint8_t type;
} TLS_CHANGE_CIPHER_SPEC;

const char *tls_change_cipher_spec_text(int change_cipher_spec);
int tls_change_cipher_spec_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);
int tls_record_set_change_cipher_spec(uint8_t *record, size_t *recordlen);
int tls_record_get_change_cipher_spec(const uint8_t *record);


// ApplicationData

int tls_record_set_application_data(uint8_t *record, size_t *recordlen,
	const uint8_t *data, size_t datalen);
int tls_record_get_application_data(uint8_t *record,
	const uint8_t **data, size_t *datalen);
int tls_application_data_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);


// Handshakes

// HelloRequest
int tls_hello_request_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);


// ClientHello, ServerHello
#define TLS_MIN_SESSION_ID_SIZE		0
#define TLS_MAX_SESSION_ID_SIZE		32


// ClientHello
int tls_record_set_handshake_client_hello(uint8_t *record, size_t *recordlen,
	int client_protocol, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len,
	const int *cipher_suites, size_t cipher_suites_count,
	const uint8_t *exts, size_t exts_len);
int tls_record_get_handshake_client_hello(const uint8_t *record,
	int *client_protocol, const uint8_t **random,
	const uint8_t **session_id, size_t *session_id_len,
	const uint8_t **cipher_suites, size_t *cipher_suites_len,
	const uint8_t **exts, size_t *exts_len);
int tls_client_hello_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);


// ServerHello
int tls_record_set_handshake_server_hello(uint8_t *record, size_t *recordlen,
	int server_protocol, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len,
	int cipher_suite, const uint8_t *exts, size_t exts_len);
int tls_record_get_handshake_server_hello(const uint8_t *record,
	int *protocol, const uint8_t **random, const uint8_t **session_id, size_t *session_id_len,
	int *cipher_suite, const uint8_t **exts, size_t *exts_len);
int tls_server_hello_print(FILE *fp, const uint8_t *server_hello, size_t len, int format, int indent);





int tls_ext_from_bytes(int *type, const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_process_client_exts(const uint8_t *exts, size_t extslen, uint8_t *out, size_t *outlen, size_t maxlen);
int tls_process_server_exts(const uint8_t *exts, size_t extslen,
	int *ec_point_format, int *supported_group, int *signature_algor);


// Certificate
int tls_record_set_handshake_certificate(uint8_t *record, size_t *recordlen,
	const uint8_t *certs, size_t certslen);
// see the impl of tls_record_get_handshake_certificate			
// a standalone cert-chain parsing function should be given			
int tls_record_get_handshake_certificate(const uint8_t *record, uint8_t *certs, size_t *certslen);

// ServerKeyExchange
int tls_server_key_exchange_print(FILE *fp, const uint8_t *ske, size_t skelen, int format, int indent);

#define TLS_MAX_SIGNATURE_SIZE	SM2_MAX_SIGNATURE_SIZE
int tls_sign_server_ecdh_params(const SM2_KEY *server_sign_key,
	const uint8_t client_random[32], const uint8_t server_random[32],
	int curve, const SM2_Z256_POINT *point, uint8_t *sig, size_t *siglen);
int tls_verify_server_ecdh_params(const SM2_KEY *server_sign_key,
	const uint8_t client_random[32], const uint8_t server_random[32],
	int curve, const SM2_Z256_POINT *point, const uint8_t *sig, size_t siglen);
int tls_record_set_handshake_server_key_exchange_ecdhe(uint8_t *record, size_t *recordlen,
	int curve, const SM2_Z256_POINT *point, const uint8_t *sig, size_t siglen);
int tls_record_get_handshake_server_key_exchange_ecdhe(const uint8_t *record,
	int *curve, SM2_Z256_POINT *point, const uint8_t **sig, size_t *siglen);
int tls_server_key_exchange_ecdhe_print(FILE *fp, const uint8_t *data, size_t datalen,
	int format, int indent);

int tlcp_record_set_handshake_server_key_exchange_pke(uint8_t *record, size_t *recordlen,
	const uint8_t *sig, size_t siglen);
int tlcp_record_get_handshake_server_key_exchange_pke(const uint8_t *record,
	const uint8_t **sig, size_t *siglen);
int tlcp_server_key_exchange_pke_print(FILE *fp, const uint8_t *sig, size_t siglen, int format, int indent);



// CertificateRequest
#define TLS_MAX_CERTIFICATE_TYPES	256
#define TLS_MAX_CA_NAMES_SIZE		(TLS_MAX_HANDSHAKE_DATA_SIZE - tls_uint8_size() - tls_uint16_size())

int tls_authorities_from_certs(uint8_t *ca_names, size_t *ca_names_len, size_t maxlen, const uint8_t *certs, size_t certslen);
int tls_authorities_issued_certificate(const uint8_t *ca_names, size_t ca_namelen, const uint8_t *certs, size_t certslen);
int tls_cert_types_accepted(const uint8_t *types, size_t types_len, const uint8_t *client_certs, size_t client_certs_len);

int tls_record_set_handshake_certificate_request(uint8_t *record, size_t *recordlen,
	const uint8_t *cert_types, size_t cert_types_len,
	const uint8_t *ca_names, size_t ca_names_len);
int tls_record_get_handshake_certificate_request(const uint8_t *record,
	const uint8_t **cert_types, size_t *cert_types_len,
	const uint8_t **ca_names, size_t *ca_names_len);
int tls_certificate_request_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);


// ServerHelloDone

int tls_record_set_handshake_server_hello_done(uint8_t *record, size_t *recordlen);
int tls_record_get_handshake_server_hello_done(const uint8_t *record);
int tls_server_hello_done_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);

// ClientKeyExchange

int tls_record_set_handshake_client_key_exchange_pke(uint8_t *record, size_t *recordlen,
	const uint8_t *enced_pms, size_t enced_pms_len);
int tls_record_get_handshake_client_key_exchange_pke(const uint8_t *record,
	const uint8_t **enced_pms, size_t *enced_pms_len);
int tls_client_key_exchange_pke_print(FILE *fp, const uint8_t *cke, size_t ckelen, int format, int indent);
int tls_client_key_exchange_print(FILE *fp, const uint8_t *cke, size_t ckelen, int format, int indent);

int tls_record_set_handshake_client_key_exchange_ecdhe(uint8_t *record, size_t *recordlen,
	const SM2_Z256_POINT *point); // shoulde we use SM2_Z256_POITN?						
int tls_record_get_handshake_client_key_exchange_ecdhe(const uint8_t *record, SM2_Z256_POINT *point);			
int tls_client_key_exchange_ecdhe_print(FILE *fp, const uint8_t *data, size_t datalen,
	int format, int indent);

// CertificateVerify

int tls_record_set_handshake_certificate_verify(uint8_t *record, size_t *recordlen,
	const uint8_t *sig, size_t siglen);
int tls_record_get_handshake_certificate_verify(const uint8_t *record,
	const uint8_t **sig, size_t *siglen);
int tls_certificate_verify_print(FILE *fp, const uint8_t *p, size_t len, int format, int indent);

typedef enum {
	TLS_client_verify_client_hello		= 0,
	TLS_client_verify_server_hello		= 1,
	TLS_client_verify_server_certificate	= 2,
	TLS_client_verify_server_key_exchange	= 3,
	TLS_client_verify_cert_request		= 4,
	TLS_client_verify_server_hello_done	= 5,
	TLS_client_verify_client_certificate	= 6,
	TLS_client_verify_client_key_exchange	= 7,
} TLS_CLIENT_VERIFY_INDEX;


/*
SM2验签要求首先提供Z值，Z值需要公钥
而在客户端提供 client_certificate 之前，服务器都不知道客户端的公钥
因此没有办法获得客户端的公钥
直到客户端发出client_certificate之后，才能够启动验证

现在的实现缓冲了所有被签名的握手消息

由于除了ClientHello之外，其他所有的消息实际上都是服务器发出的
因此服务器只需要缓存ClientHello即可

实际上只有SM2签名才需要这么复杂！
*/

typedef struct {
	TLS_CLIENT_VERIFY_INDEX index;
	uint8_t *handshake[8]; // Record data only, no record header
	size_t handshake_len[8];
} TLS_CLIENT_VERIFY_CTX;

int tls_client_verify_init(TLS_CLIENT_VERIFY_CTX *ctx);
int tls_client_verify_update(TLS_CLIENT_VERIFY_CTX *ctx, const uint8_t *handshake, size_t handshake_len);
int tls_client_verify_finish(TLS_CLIENT_VERIFY_CTX *ctx, const uint8_t *sig, size_t siglen, const SM2_KEY *public_key);
void tls_client_verify_cleanup(TLS_CLIENT_VERIFY_CTX *ctx);

// Finished
// FIXME: to support TLS 1.3  need MIN, MAX or TLS12, TLS13, TLCP...			
#define TLS_VERIFY_DATA_SIZE 12 // TLS 1.3 use longer verify_data (>= 12 bytes)		
#define TLS_FINISHED_RECORD_SIZE	(TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE + TLS_VERIFY_DATA_SIZE) // 21
#define TLS_MAX_PADDING_SIZE		(1 + 255)
#define TLS_MAC_SIZE			SM3_HMAC_SIZE
#define TLS_FINISHED_RECORD_BUF_SIZE	(TLS_FINISHED_RECORD_SIZE + TLS_MAC_SIZE + TLS_MAX_PADDING_SIZE) // 309


int tls_record_set_handshake_finished(uint8_t *record, size_t *recordlen,
	const uint8_t *verify_data, size_t verify_data_len);
int tls_record_get_handshake_finished(const uint8_t *record,
	const uint8_t **verify_data, size_t *verify_data_len);
int tls_finished_print(FILE *fp, const uint8_t *a, size_t len, int format, int indent);




// KeyUpdate
enum {
	TLS_key_update_requested	= 0,
	TLS_key_update_not_requested	= 1,
	TLS_key_update_reserved_max	= 255,
};





enum {
	TLS_server_mode = 0,
	TLS_client_mode = 1,
};

#define TLS_MAX_CIPHER_SUITES_COUNT	64


typedef struct {
	int sig_alg;
	uint8_t *name;
	size_t namelen;
	uint8_t *certs;
	size_t certslen;
} TLS_CERTS;


#define TLS13_SCT_MAX_SIZE  (32 + 8 + 2 + SM2_MAX_SIGNATURE_SIZE) // = 114




typedef struct {
	int is_client;

	int quiet;

	int protocol;


	int cipher_suites[TLS_MAX_CIPHER_SUITES_COUNT];
	size_t cipher_suites_cnt;

	uint8_t cert_chains[8192];
	size_t cert_chains_len;
	size_t cert_chains_cnt; // 这是一个多余的值，不应该存储多余的值
	size_t cert_chain_idx;
	uint8_t *certs;	// 这里应该改为cert_chain，我们将certs表示为互相独立的证书
	size_t certslen;


	// 每个证书链都应该有附带的status_request和sct信息
	// status_request_ocsp_response
	// sct_list 证书透明有关的信息，这是一个长期的信息
	// 这两个信息实际上都是证书链的扩展，因此这里我们需要准备相应的数据了
	// 这里还是暂时不给出好了


	// 这里面需要解决的是，TLCP和TLS中证书链和密钥数量不对等的问题，一个TLCP证书链需要2个密钥
	X509_KEY x509_keys[4];
	X509_KEY enc_keys[4];

	size_t x509_keys_cnt;
	X509_KEY signkey;
	X509_KEY kenckey;

	// 对于客户端来说，需要提供所有的CA证书，注意这里不是证书链，而是一个个独立的证书
	// 对于服务器来说，在certificate_request中，需要从这些证书中提取dn_names，并发送给客户端，然后再验证客户端证书
	uint8_t *cacerts;
	size_t cacertslen;
	int verify_depth;







	// NewSessionTicket
	int new_session_ticket;
	int new_session_ticket_cnt;
	SM4_KEY *session_ticket_key;
	SM4_KEY _session_ticket_key;


	// KeyUpdate
	size_t key_update_seq_num_limit;
	size_t key_update_data_size_limit;


	// extensions

	// 0. server_name (SNI)
	// server_name is connection only

	// 5. status_request
	// list of (uint24array)CertificateEntry.extensions.status_request.response
	uint8_t status_request_ocsp_responses[512];
	size_t status_request_ocsp_responses_len;

	// 10. supported_gruops
	int supported_groups[32];
	size_t supported_groups_cnt;

	// 13. signature_algorithms
	int signature_algorithms[2];
	size_t signature_algorithms_cnt;

	// 18. signed_certificate_timestamp
	int signed_certificate_timestamp;
	uint8_t signed_certificate_timestamp_lists[512];
	size_t signed_certificate_timestamp_lists_len;

	// 35. session_ticket
	// session_ticket only supported in tls12

	// 41. pre_shared_key
	//	no flag

	// 42. early_data
	int early_data;
	int max_early_data_size;

	// 43. supported_versions
	int supported_versions[4];
	size_t supported_versions_cnt;

	// 44. cookie
	int cookie;
	SM4_KEY cookie_key;

	// 46. psk_key_exchange_modes
	int psk_key_exchange_modes;

	// 51. key_share
	size_t key_exchanges_cnt;

} TLS_CTX;




int tls_ctx_init(TLS_CTX *ctx, int protocol, int is_client);
int tls_ctx_set_cipher_suites(TLS_CTX *ctx, const int *cipher_suites, size_t cipher_suites_cnt);
int tls_ctx_set_signature_algorithms(TLS_CTX *ctx, const int *sig_algs, size_t sig_algs_cnt);
int tls_ctx_set_ca_certificates(TLS_CTX *ctx, const char *cacertsfile, int depth);
int tls_ctx_set_certificate_and_key(TLS_CTX *ctx, const char *chainfile,
	const char *keyfile, const char *keypass);
int tls_ctx_set_tlcp_server_certificate_and_keys(TLS_CTX *ctx, const char *chainfile,
	const char *signkeyfile, const char *signkeypass,
	const char *kenckeyfile, const char *kenckeypass);
void tls_ctx_cleanup(TLS_CTX *ctx);

int tls_ctx_add_certificate_chain_and_key(TLS_CTX *ctx, const char *chainfile,
	const char *keyfile, const char *keypass);

int tls_ctx_add_certificate_list_and_key(TLS_CTX *ctx, const char *chainfile,
	const uint8_t *entity_status_request_ocsp_responses, size_t entity_status_request_ocsp_responses_len, // optional
	const uint8_t *entity_signed_certificate_timestamp_list, size_t entity_signed_certificate_timestamp_list_len, // optional
	const char *keyfile, const char *keypass);




#define TLS_MAX_CERTIFICATES_SIZE	2048
#define TLS_DEFAULT_VERIFY_DEPTH	4
#define TLS_MAX_VERIFY_DEPTH		5



/*
#define SSL_ERROR_WANT_READ		-1001 // 是否考虑把这两个错误以0的方式返回去
#define SSL_ERROR_WANT_WRITE		-1002 // 同上
#define SSL_ERROR_ZERO_RETURN		-1003
#define SSL_ERROR_SYSCALL		-1004
*/

#define TLS_ERROR_RECV_AGAIN		-1000	// SSL_ERROR_WANT_READ
#define TLS_ERROR_SEND_AGAIN		-1001	// SSL_ERROR_WANT_WRITE
#define TLS_ERROR_TCP_CLOSED		-1002	// SSL_ERROR_ZERO_RETURN
#define TLS_ERROR_SYSCALL		-1003	// SSL_ERROR_SYSCALL


/*
#define TLS_ERR_WANT_READ		-1000
#define TLS_ERR_WANT_WRITE		-1001
#define TLS_ERR_TCP_CLOSED		-1002
#define TLS_ERR_SYSCALL			-1003
*/



enum {
	TLS_state_handshake_init = 0,
	TLS_state_client_hello,
	TLS_state_early_data,
	TLS_state_end_of_early_data,
	TLS_state_hello_retry_request,
	TLS_state_client_hello_again,
	TLS_state_server_hello,
	TLS_state_encrypted_extensions,
	TLS_state_server_certificate,
	TLS_state_server_key_exchange,
	TLS_state_certificate_request,
	TLS_state_server_hello_done,
	TLS_state_client_certificate,
	TLS_state_client_key_exchange,
	TLS_state_certificate_verify,
	TLS_state_client_certificate_verify,
	TLS_state_generate_keys,
	TLS_state_client_change_cipher_spec,
	TLS_state_client_finished,
	TLS_state_server_change_cipher_spec,
	TLS_state_server_finished,
	TLS_state_new_session_ticket,
	TLS_state_handshake_over,


	TLS_state_recv_record_header,
	TLS_state_recv_record_data,
};



typedef struct {
	int is_client; // 这个在CTX中应该是有的

	int quiet;

	tls_socket_t sock;

	TLS_CTX *ctx;

	// handshake state for state machine
	int state;


	uint8_t record[TLS_MAX_RECORD_SIZE];
	size_t record_offset; // offset of processed record
	size_t recordlen;
	uint8_t plain_record[TLS_MAX_RECORD_SIZE];
	size_t plain_recordlen;


	uint8_t databuf[TLS_MAX_RECORD_SIZE]; // 需要替换为plain_record
	uint8_t *data; // 让data指向plain_record
	size_t datalen;




	int protocol;

	int key_exchange_modes;

	int cipher_suite;
	const DIGEST *digest;
	const BLOCK_CIPHER *cipher;


	uint8_t session_id[32];
	size_t session_id_len;
	uint8_t client_random[32];
	uint8_t server_random[32];


	// 一般来说我们只要保存对方发过来的证书，因为己方的证书都在CTX中，对吗？
	uint8_t server_certs[TLS_MAX_CERTIFICATES_SIZE]; // TODO: use ptr and malloc			
	size_t server_certs_len;
	uint8_t client_certs[TLS_MAX_CERTIFICATES_SIZE];
	size_t client_certs_len;


	// 己方的证书链，指向TLS_CTX中的cert_chains
	const uint8_t *cert_chain;
	size_t cert_chain_len;
	int cert_chain_idx; // 这样就指向了CTX中的密钥

	int sig_alg;


	uint8_t peer_cert_chain[TLS_MAX_CERTIFICATES_SIZE];
	size_t peer_cert_chain_len;


	X509_KEY sign_key;
	X509_KEY kenc_key; // 应该作为服务器的SM2加密
	X509_KEY server_enc_key;

	int verify_result;


	// transcript hash
	SM3_CTX sm3_ctx;
	DIGEST_CTX dgst_ctx;


	// secrets
	SM3_HMAC_CTX client_write_mac_ctx;
	SM3_HMAC_CTX server_write_mac_ctx;
	SM4_KEY client_write_enc_key;
	SM4_KEY server_write_enc_key;
	uint8_t client_seq_num[8];
	uint8_t server_seq_num[8];

	uint8_t client_write_iv[12]; // tls13
	uint8_t server_write_iv[12]; // tls13
	BLOCK_CIPHER_KEY client_write_key;
	BLOCK_CIPHER_KEY server_write_key;

	uint8_t pre_master_secret[48]; // 是否可以重用master_secret作为pre_master_secret呢？			
	uint8_t master_secret[48];
	uint8_t resumption_master_secret[48];

	uint8_t key_block[96];

	uint8_t early_secret[32];
	uint8_t handshake_secret[32];
	uint8_t client_handshake_traffic_secret[32];
	uint8_t server_handshake_traffic_secret[32];
	uint8_t client_application_traffic_secret[32];
	uint8_t server_application_traffic_secret[32];


	SM2_SIGN_CTX sign_ctx;
	TLS_CLIENT_VERIFY_CTX client_verify_ctx;



	// 所有这些命名为ecdh的都需要替换掉
	uint16_t ecdh_named_curve;
	X509_KEY ecdh_keys[2];
	size_t ecdh_keys_cnt;
	X509_KEY ecdh_key;
	uint8_t peer_ecdh_point[65];
	size_t peer_ecdh_point_len;



	// CertificateRequest.signature_algorithms =
	//   common(ClientHello.signature_algorithms, ctx->signature_algorithms)
	/*
	int signature_algorithms[2];
	size_t signature_algorithms_cnt;
	*/


	// handshake messages
	int hello_retry_request;
	int certificate_request;
	//int new_session_ticket;

	// KeyUpdate
	size_t client_data_size;
	size_t server_data_size;

	// extensions

	// 0. server_name
	// server_name is client only, server should not response server_name ext
	int server_name;
	uint8_t host_name[256];
	size_t host_name_len;

	// 5. status_request
	int status_request;
	// ClientHello.status_request set by app
	const uint8_t *status_request_responder_id_list;
	size_t status_request_responder_id_list_len;
	const uint8_t *status_request_exts;
	size_t status_request_exts_len;
	// ServerCertificate.CertificateEntry.status_request
	// 在选择好证书之后，这些值应该指向ctx->status_request_ocsp_responses
	// 但是有可能指针为空或者长度为0
	// 如果客户端发送了status_request，还需要进一步检查是否匹配，如果不匹配，需要设置为0
	const uint8_t *status_request_ocsp_response;
	size_t status_request_ocsp_response_len;

	// 10. supported_gruops
	int supported_groups[32];
	size_t supported_groups_cnt;


	// 13. signature_algorithms
	int signature_algorithms[2];
	size_t signature_algorithms_cnt;

	// 18. signed_certificate_timestamp
	int signed_certificate_timestamp;
	const uint8_t *signed_certificate_timestamp_list;
	size_t signed_certificate_timestamp_list_len;

	// 35. session_ticket
	// NewSessionTicket
	int new_session_ticket;
	int new_session_ticket_cnt;

	// 41. pre_shared_key
	int pre_shared_key;
	uint8_t psk_identities[512];
	size_t psk_identities_len;
	int psk_cipher_suites[8];
	size_t psk_cipher_suites_cnt;
	uint8_t psk_keys[32 * 8];
	size_t psk_keys_len;


	const uint8_t *psk_identity;
	size_t psk_identity_len;
	uint8_t psk[32]; // 这应该改为一个指针
	size_t psk_len;
	int selected_psk_identity;


	// session_ticket
	const char *session_in;
	const char *session_out;

	int client_certificate_verify; // TLS1.2 TLCP需要这个


	// 42. early_data
	int early_data;
	size_t max_early_data_size;
	uint8_t early_data_buf[8192];
	size_t early_data_len;

	// 44. cookie
	int cookie;
	uint8_t cookie_buf[256];
	size_t cookie_len;

	// 51. key_share
	int key_share;
	X509_KEY key_exchanges[2];
	size_t key_exchanges_cnt;
	size_t key_exchange_idx;
	int key_exchange_group;
	uint8_t peer_key_exchange[65]; //这个似乎应该替换掉
	size_t peer_key_exchange_len;

} TLS_CONNECT;


#define TLS_MAX_EXTENSIONS_SIZE 512 // FIXME: no reason to give fixed max length			



int tls_send_record(TLS_CONNECT *conn);
int tls_recv_record(TLS_CONNECT *conn);


// TLS 1.3 Handshake messages

// ClientHello/ServerHello
//	set/get functions use tls_ functions
int tls13_client_hello_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);
int tls13_server_hello_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);


// HelloRetryRequest

int tls13_record_set_handshake_hello_retry_request(uint8_t *record, size_t *recordlen,
	int legacy_version, const uint8_t random[32],
	const uint8_t *legacy_session_id_echo, size_t legacy_session_id_echo_len,
	int cipher_suite, int legacy_compress_meth,
	const uint8_t *exts, size_t extslen);
int tls13_record_get_handshake_hello_retry_request(uint8_t *record,
	int *legacy_version, const uint8_t **random,
	const uint8_t **legacy_session_id_echo, size_t *legacy_session_id_echo_len,
	int *cipher_suite, int *legacy_compress_meth,
	const uint8_t **exts, size_t *extslen);
int tls13_hello_retry_request_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);


// Certificate

int tls13_certificate_entry_to_bytes(const uint8_t *cert, size_t certlen,
	const uint8_t *status_request_ocsp_response, size_t status_request_ocsp_response_len,
	const uint8_t *signed_certificate_timestamp, size_t signed_certificate_timestamp_len,
	uint8_t **out, size_t *outlen);
int tls13_certificate_entry_from_bytes(const uint8_t **cert, size_t *certlen,
	const uint8_t **status_request_ocsp_response, size_t *status_request_ocsp_response_len,
	const uint8_t **signed_certificate_timestamp, size_t *signed_certificate_timestamp_len,
	const uint8_t **in, size_t *inlen);
int tls13_record_set_handshake_certificate(uint8_t *record, size_t *recordlen,
	const uint8_t *request_context, size_t request_context_len,
	const uint8_t *certs, size_t certslen,
	const uint8_t *entity_status_request_ocsp_response, size_t entity_status_request_ocsp_response_len,
	const uint8_t *entity_signed_certificate_timestamp, size_t entity_signed_certificate_timestamp_len);
int tls13_record_get_handshake_certificate(const uint8_t *record,
	const uint8_t **request_context, size_t *request_context_len,
	uint8_t *cert_chain, size_t *cert_chain_len, size_t cert_chain_maxlen,
	const uint8_t **entity_status_request_ocsp_response, size_t *entity_status_request_ocsp_response_len,
	const uint8_t **entity_signed_certificate_timestamp, size_t *entity_signed_certificate_timestamp_len);
int tls13_certificate_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);


// CertificateVerify

int tls13_record_set_handshake_certificate_verify(uint8_t *record, size_t *recordlen,
	int sig_alg, const uint8_t *sig, size_t siglen);
int tls13_record_get_handshake_certificate_verify(const uint8_t *record,
	int *sig_alg, const uint8_t **sig, size_t *siglen);
int tls13_certificate_verify_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);


// CertificateRequest

int tls13_record_set_handshake_certificate_request(uint8_t *record, size_t *recordlen,
	const uint8_t *request_context, size_t request_context_len,
	const uint8_t *exts, size_t extslen);
int tls13_record_set_handshake_certificate_request_default(uint8_t *record, size_t *recordlen);
int tls13_record_get_handshake_certificate_request(const uint8_t *record,
	const uint8_t **requst_context, size_t *request_context_len,
	const uint8_t **exts, size_t *exts_len);
int tls13_certificate_request_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);


// EndOfEarlyData

int tls13_record_set_handshake_end_of_early_data(uint8_t *record, size_t *recordlen);
int tls13_record_get_handshake_end_of_early_data(uint8_t *record);
int tls13_end_of_early_data_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);


// Finished

int tls13_record_set_handshake_finished(uint8_t *record, size_t *recordlen,
	const uint8_t *verify_data, size_t verify_data_len);
int tls13_record_get_handshake_finished(const uint8_t *record,
	const uint8_t **verify_data, size_t *verify_data_len);
int tls13_finished_print(FILE *fp, int fmt, int ind, const uint8_t *data, size_t datalen);


// KeyUpdate

int tls13_record_set_handshake_key_update(uint8_t *record, size_t *recordlen,
	int request_update);
int tls13_record_get_handshake_key_update(uint8_t *record, int *request_update);
int tls13_key_update_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);




// NewSessionTicket

int tls13_encrypt_ticket(const SM4_KEY *key, const uint8_t resumption_master_secret[48],
	int protocol_version, int cipher_suite, uint32_t ticket_issue_time,  uint32_t ticket_lifetime,
	uint8_t *out, size_t *outlen);
int tls13_decrypt_ticket(const SM4_KEY *key, const uint8_t *in, size_t inlen,
	uint8_t resumption_master_secret[48], int *protocol_version, int *cipher_suite,
	uint32_t *ticket_issue_time, uint32_t *ticket_lifetime);
int tls13_ticket_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
int tls13_record_set_handshake_new_session_ticket(uint8_t *record, size_t *recordlen,
	uint32_t ticket_lifetime, uint32_t ticket_age_add,
	const uint8_t *ticket_nonce, size_t ticket_nonce_len,
	const uint8_t *ticket, size_t ticketlen,
	const uint8_t *exts, size_t extslen);
int tls13_record_get_handshake_new_session_ticket(uint8_t *record,
	uint32_t *ticket_lifetime, uint32_t *ticket_age_add,
	const uint8_t **ticket_nonce, size_t *ticket_nonce_len,
	const uint8_t **ticket, size_t *ticketlen,
	const uint8_t **exts, size_t *extslen);
int tls13_new_session_ticket_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);










int tls_generate_keys(TLS_CONNECT *conn);

int tls13_update_client_application_keys(TLS_CONNECT *conn);
int tls13_update_server_application_keys(TLS_CONNECT *conn);





// tls12 client
int tls_send_client_hello(TLS_CONNECT *conn);
int tls_recv_server_hello(TLS_CONNECT *conn);
int tls_recv_server_certificate(TLS_CONNECT *conn);
int tls_recv_server_key_exchange(TLS_CONNECT *conn);
int tls_recv_certificate_request(TLS_CONNECT *conn);
int tls_recv_server_hello_done(TLS_CONNECT *conn);
int tls_send_client_certificate(TLS_CONNECT *conn);
int tls_send_client_key_exchange(TLS_CONNECT *conn);
int tls_send_certificate_verify(TLS_CONNECT *conn);
int tls_send_change_cipher_spec(TLS_CONNECT *conn);
int tls_recv_change_cipher_spec(TLS_CONNECT *conn);
int tls_send_client_finished(TLS_CONNECT *conn);
int tls_recv_server_finished(TLS_CONNECT *conn);


// tls12 server
int tls_recv_client_hello(TLS_CONNECT *conn);
int tls_send_server_hello(TLS_CONNECT *conn);
int tls_send_server_certificate(TLS_CONNECT *conn);
int tls_send_server_key_exchange(TLS_CONNECT *conn);
int tls_send_certificate_request(TLS_CONNECT *conn);
int tls_send_server_hello_done(TLS_CONNECT *conn);
int tls_recv_client_certificate(TLS_CONNECT *conn);
int tls_recv_client_key_exchange(TLS_CONNECT *conn);
int tls_recv_certificate_verify(TLS_CONNECT *conn);
int tls_recv_client_finished(TLS_CONNECT *conn);
int tls_send_server_finished(TLS_CONNECT *conn);


int tlcp_send_client_hello(TLS_CONNECT *conn);
int tlcp_recv_client_hello(TLS_CONNECT *conn);
int tlcp_send_server_key_exchange(TLS_CONNECT *conn);
int tlcp_recv_server_key_exchange(TLS_CONNECT *conn);
int tlcp_generate_keys(TLS_CONNECT *conn);
int tlcp_send_client_key_exchange(TLS_CONNECT *conn);
int tlcp_recv_client_key_exchange(TLS_CONNECT *conn);






// tls13 client
int tls13_send_client_hello(TLS_CONNECT *conn);
int tls13_recv_hello_retry_request(TLS_CONNECT *conn);
int tls13_send_client_hello_again(TLS_CONNECT *conn);
int tls13_recv_server_hello(TLS_CONNECT *conn);
int tls13_recv_encrypted_extensions(TLS_CONNECT *conn);
int tls13_recv_certificate_request(TLS_CONNECT *conn);
int tls13_recv_server_certificate(TLS_CONNECT *conn);
int tls13_recv_certificate_verify(TLS_CONNECT *conn);
int tls13_recv_server_finished(TLS_CONNECT *conn);
int tls13_send_client_certificate(TLS_CONNECT *conn);
int tls13_send_client_certificate_verify(TLS_CONNECT *conn);
int tls13_send_end_of_early_data(TLS_CONNECT *conn);
int tls13_send_client_finished(TLS_CONNECT *conn);
int tls13_recv_new_session_ticket(TLS_CONNECT *conn);

// tls13 server
int tls13_recv_client_hello(TLS_CONNECT *conn);
int tls13_send_hello_retry_request(TLS_CONNECT *conn);
int tls13_recv_client_hello_again(TLS_CONNECT *conn);
int tls13_send_server_hello(TLS_CONNECT *conn);
int tls13_send_encrypted_extensions(TLS_CONNECT *conn);
int tls13_send_certificate_request(TLS_CONNECT *conn);
int tls13_send_server_certificate(TLS_CONNECT *conn);
int tls13_send_server_certificate_verify(TLS_CONNECT *conn);
int tls13_send_server_finished(TLS_CONNECT *conn);
int tls13_recv_client_certificate(TLS_CONNECT *conn);
int tls13_recv_end_of_early_data(TLS_CONNECT *conn);
int tls13_recv_client_finished(TLS_CONNECT *conn);
int tls13_send_new_session_ticket(TLS_CONNECT *conn);


// tls13 client/server
int tls13_send_key_update(TLS_CONNECT *conn, int request_update);
int tls13_recv_key_update(TLS_CONNECT *conn);


void tls_clean_record(TLS_CONNECT *conn);

int tls_print_record(FILE *fp, int fmt, int ind, const char *label, TLS_CONNECT *conn);

int tls_init(TLS_CONNECT *conn, TLS_CTX *ctx);
int tls_set_hostname(TLS_CONNECT *conn, const char *hostname);
int tls_set_socket(TLS_CONNECT *conn, tls_socket_t sock);


int tls_do_handshake(TLS_CONNECT *conn);

int tls_send(TLS_CONNECT *conn, const uint8_t *in, size_t inlen, size_t *sentlen);
int tls_recv(TLS_CONNECT *conn, uint8_t *out, size_t outlen, size_t *recvlen);
int tls_shutdown(TLS_CONNECT *conn);
void tls_cleanup(TLS_CONNECT *conn);

int tlcp_do_connect(TLS_CONNECT *conn);
int tlcp_do_accept(TLS_CONNECT *conn);
int tls12_do_connect(TLS_CONNECT *conn);
int tls12_do_accept(TLS_CONNECT *conn);



int tls13_do_connect(TLS_CONNECT *conn);
int tls13_do_accept(TLS_CONNECT *conn);

int tls13_connect(TLS_CONNECT *conn, const char *hostname, int port, FILE *server_cacerts_fp,
	FILE *client_certs_fp, const SM2_KEY *client_sign_key);
int tls13_accept(TLS_CONNECT *conn, int port,
	FILE *server_certs_fp, const SM2_KEY *server_sign_key,
	FILE *client_cacerts_fp);
int tls13_send(TLS_CONNECT *conn, const uint8_t *data, size_t datalen, size_t *sentlen);
int tls13_recv(TLS_CONNECT *conn, uint8_t *out, size_t outlen, size_t *recvlen);




#define TLS13_SM2_ID		"TLSv1.3+GM+Cipher+Suite"
#define TLS13_SM2_ID_LENGTH	(sizeof(TLS13_SM2_ID)-1)




int tls_send_alert(TLS_CONNECT *conn, int alert);
int tls_send_warning(TLS_CONNECT *conn, int alert);


int tls13_send_alert(TLS_CONNECT *conn, int alert);




int tls_process_client_hello_exts(const uint8_t *exts, size_t extslen, uint8_t *out, size_t *outlen, size_t maxlen);
int tls_process_server_hello_exts(const uint8_t *exts, size_t extslen,
	int *ec_point_format, int *supported_group, int *signature_algor);


int tls13_encrypted_extensions_print(FILE *fp, int fmt, int ind, const uint8_t *data, size_t datalen);

int tls13_extension_print(FILE *fp, int fmt, int ind,
	int handshake_type, int ext_type, const uint8_t *ext_data, size_t ext_datalen);
int tls13_extensions_print(FILE *fp, int fmt, int ind,
	int handshake_type, const uint8_t *exts, size_t extslen);

int tls13_certificate_print(FILE *fp, int fmt, int ind, const uint8_t *cert, size_t certlen);
int tls13_certificate_request_print(FILE *fp, int fmt, int ind, const uint8_t *cert, size_t certlen);
int tls13_certificate_verify_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);
int tls13_record_print(FILE *fp, int format, int indent, const uint8_t *record, size_t recordlen);











int tls13_gcm_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], int record_type,
	const uint8_t *in, size_t inlen, size_t padding_len, // TLSInnerPlaintext.content
	uint8_t *out, size_t *outlen); // TLSCiphertext.encrypted_record
int tls13_gcm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	int *record_type, uint8_t *out, size_t *outlen);


#ifdef ENABLE_TLS_DEBUG
#	define tls_trace(s) fprintf(stderr,(s))
#	define tls_record_trace(fp,rec,reclen,fmt,ind)  tls_record_print(fp,rec,reclen,fmt,ind)
#	define tls_encrypted_record_trace(fp,rec,reclen,fmt,ind)  tls_encrypted_record_print(fp,rec,reclen,fmt,ind)
#	define tlcp_record_trace(fp,rec,reclen,fmt,ind)  tlcp_record_print(fp,rec,reclen,fmt,ind)
#	define tls12_record_trace(fp,rec,reclen,fmt,ind)  tls12_record_print(fp,rec,reclen,fmt,ind)
#	define tls13_record_trace(fp,rec,reclen,fmt,ind)  tls13_record_print(fp,fmt,ind,rec,reclen)
#else
#	define tls_trace(s)
#	define tls_record_trace(fp,rec,reclen,fmt,ind)
#	define tls_encrypted_record_trace(fp,rec,reclen,fmt,ind)
#	define tlcp_record_trace(fp,rec,reclen,fmt,ind)
#	define tls12_record_trace(fp,rec,reclen,fmt,ind)
#	define tls13_record_trace(fp,rec,reclen,fmt,ind)
#endif

int tls_encrypted_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent);











int tls13_set_session_resumption(TLS_CONNECT *conn, const char *session_file);





int tls13_ctx_set_session_ticket_key(TLS_CTX *ctx, const uint8_t *key, size_t keylen);
int tls13_ctx_enable_new_session_ticket(TLS_CTX *ctx, size_t new_session_ticket_cnt);
int tls13_enable_new_session_ticket(TLS_CONNECT *conn, size_t new_session_ticket_cnt);



// 只是意味着保存NewSessionTicket
int tls13_set_session_outfile(TLS_CONNECT *conn, const char *file);










int tls13_enable_pre_shared_key(TLS_CONNECT *conn, int enable);


int tls13_add_pre_shared_key(TLS_CONNECT *conn, const uint8_t *identity, size_t identitylen,
	const uint8_t *pre_shared_key, size_t pre_shared_key_len,
	int cipher_suite,
	uint32_t age);


int tls13_add_pre_shared_key_from_session_file(TLS_CONNECT *conn, FILE *fp);

int tls13_ctx_set_psk_key_exchange_modes(TLS_CTX *ctx, int psk_ke, int psk_dhe_ke);


int tls13_verify_psk_binder(const DIGEST *digest,
	const uint8_t *pre_shared_key, size_t pre_shared_key_len,
	const DIGEST_CTX *truncated_client_hello_dgst_ctx,
	const uint8_t *binder, size_t binderlen);

int tls_ctx_set_supported_groups(TLS_CTX *ctx, const int *groups, size_t groups_cnt);
int tls13_set_psk_key_exchange_modes(TLS_CONNECT *conn, int psk_ke, int psk_dhe_ke);

int tls13_psk_key_exchange_modes_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen);


enum {
	TLS_name_type_host_name		= 0,
	TLS_name_type_preserved_max	= 255,
};


#define tls_ext_data(ext)	((ext) + 4)

int tls_ext_to_bytes(int ext_type, const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen);







// TLS 1.3 cipher/key related

int tls13_random_generate(uint8_t random[32]);
int tls13_cipher_suite_get(int cipher_suite, const BLOCK_CIPHER **cipher, const DIGEST **digest);
int tls13_padding_len_rand(size_t *padding_len);

int gcm_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag);
int gcm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out);
int tls13_gcm_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], int record_type,
	const uint8_t *in, size_t inlen, size_t padding_len, // TLSInnerPlaintext.content
	uint8_t *out, size_t *outlen); // TLSCiphertext.encrypted_record;
int tls13_gcm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	int *record_type, uint8_t *out, size_t *outlen);
int tls13_record_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], const uint8_t *record, size_t recordlen, size_t padding_len,
	uint8_t *enced_record, size_t *enced_recordlen);
int tls13_record_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t iv[12],
	const uint8_t seq_num[8], const uint8_t *enced_record, size_t enced_recordlen,
	uint8_t *record, size_t *recordlen);


int tls13_hkdf_extract(const DIGEST *digest, const uint8_t salt[32], const uint8_t in[32], uint8_t out[32]);
int tls13_hkdf_expand_label(const DIGEST *digest, const uint8_t secret[32],
	const char *label, const uint8_t *context, size_t context_len,
	size_t outlen, uint8_t *out);
int tls13_derive_secret(const uint8_t secret[32], const char *label, const DIGEST_CTX *dgst_ctx, uint8_t out[32]);

int tls13_sign_certificate_verify(int tls_mode, int sig_alg,
	X509_KEY *sign_key, const DIGEST_CTX *tbs_dgst_ctx,
	uint8_t *sig, size_t *siglen);
int tls13_verify_certificate_verify(int tls_mode, int sig_alg,
	const X509_KEY *public_key, const DIGEST_CTX *tbs_dgst_ctx,
	const uint8_t *sig, size_t siglen);

int tls13_compute_verify_data(const uint8_t *handshake_traffic_secret,
	const DIGEST_CTX *dgst_ctx, uint8_t *verify_data, size_t *verify_data_len);

int tls13_generate_early_data_keys(TLS_CONNECT *conn);






int tls13_process_new_session_ticket(TLS_CONNECT *conn);





// Extensions



// 0. server_name (sni)
int tls_server_name_ext_to_bytes(const uint8_t *host_name, size_t host_name_len, uint8_t **out, size_t *outlen);
int tls_server_name_from_bytes(const uint8_t **host_name, size_t *host_name_len,
	const uint8_t *ext_data, size_t ext_datalen);
int tls_server_name_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen);
int tls_set_server_name(TLS_CONNECT *conn, const uint8_t *host_name, size_t host_name_len);

// 5. status_request (ocsp stapling)
enum {
	TLS_certificate_status_type_ocsp = 1,
};

int ocsp_response_verify(const uint8_t *ocsp_response, size_t ocsp_response_len,
	const uint8_t *ca_certs, size_t ca_certs_len);

int tls_ocsp_status_request_to_bytes(
	const uint8_t *responder_id_list, size_t responder_id_list_len,
	const uint8_t *request_exts, size_t request_exts_len,
	uint8_t **out, size_t *outlen);
int tls_ocsp_status_request_from_bytes(
	const uint8_t **responder_id_list, size_t *responder_id_list_len,
	const uint8_t **request_exts, size_t *request_exts_len,
	const uint8_t **in, size_t *inlen);
int tls_ocsp_status_request_print(FILE *fp, int fmt, int ind,
	const char *label, const uint8_t *ext_data, size_t ext_datalen);
int tls_client_status_request_ext_to_bytes(int status_type,
	const uint8_t *responder_id_list, size_t responder_id_list_len,
	const uint8_t *request_exts, size_t request_exts_len,
	uint8_t **out, size_t *outlen);
int tls_client_status_request_from_bytes(int *status_type,
	const uint8_t **responder_id_list, size_t *responder_id_list_len,
	const uint8_t **request_exts, size_t *request_exts_len,
	const uint8_t *ext_data, size_t ext_datalen);
int tls_client_status_request_print(FILE *fp, int fmt, int ind,
	const uint8_t *ext_data, size_t ext_datalen);
int tls13_set_client_status_request(TLS_CONNECT *conn,
	const uint8_t *status_request_responder_id_list, size_t status_request_responder_id_list_len, // optional
	const uint8_t *status_request_exts, size_t status_request_exts_len); // optional

int tls_server_status_request_ext_to_bytes(const uint8_t *ocsp_response, size_t ocsp_response_len,
	uint8_t **out, size_t *outlen);
int tls_server_status_request_from_bytes(const uint8_t **ocsp_response, size_t *ocsp_response_len,
	const uint8_t *ext_data, size_t ext_datalen);
int tls_server_status_request_print(FILE *fp, int fmt, int ind,
	const uint8_t *ext_data, size_t ext_datalen);

int tls_ocsp_response_match_status_request(
	const uint8_t *status_request_ocsp_response, size_t status_request_ocsp_response_len,
	const uint8_t *responder_id_list, size_t responder_id_list_len,
	const uint8_t *request_exts, size_t request_exts_len);

// 10. supported_groups
int tls_supported_groups_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);
int tls_supported_groups_ext_to_bytes(const int *groups, size_t groups_cnt,
	uint8_t **out, size_t *outlen);
int tls_process_client_supported_groups(const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen);
int tls_process_server_supported_groups(const uint8_t *ext_data, size_t ext_datalen);

int tls_process_supported_groups(const uint8_t *ext_data, size_t ext_datalen,
	const int *local_groups, size_t local_groups_cnt,
	int *common_groups, size_t *common_groups_cnt, size_t max_cnt);

// 11. ec_point_format
int tls_ec_point_formats_ext_to_bytes(const int *formats, size_t formats_cnt,
	uint8_t **out, size_t *outlen);
int tls_process_client_ec_point_formats(const uint8_t *ext_data, size_t ext_datalen,
	uint8_t **out, size_t *outlen);
int tls_process_server_ec_point_formats(const uint8_t *ext_data, size_t ext_datalen);

// 13. signature_algorithms
int tls_signature_algorithms_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);
int tls_signature_algorithms_ext_to_bytes_ex(int ext_type, const int *algs, size_t algs_cnt,
	uint8_t **out, size_t *outlen);
int tls_signature_algorithms_ext_to_bytes(const int *algs, size_t algs_cnt,
	uint8_t **out, size_t *outlen);
// 这个扩展不解码，直接就处理了
int tls_process_signature_algorithms(const uint8_t *ext_data, size_t ext_datalen,
	const int *local_sig_algs, size_t local_sig_algs_cnt,
	int *common_sig_algs, size_t *common_sig_algs_cnt, size_t max_cnt);

// 18. signed_certificate_timestamp (certificate transparency, CT)
int tls_signed_certificate_timestamp_entry_to_bytes(const uint8_t key_id[32],
	uint64_t timestamp, const uint8_t *signature, size_t signature_len,
	uint8_t **out, size_t *outlen);
int tls_signed_certificate_timestamp_entry_from_bytes(const uint8_t **key_id,
	uint64_t *timestamp, const uint8_t **signature, size_t *signature_len,
	const uint8_t **in, size_t *inlen);
int tls_signed_certificate_timestamp_ext_to_bytes(const uint8_t *sct_list, size_t sct_list_len,
	uint8_t **out, size_t *outlen);
int tls_signed_certificate_timestamp_from_bytes(const uint8_t **sct_list, size_t *sct_list_len,
	const uint8_t **in, size_t *inlen);
int tls_signed_certificate_timestamp_print(FILE *fp, int fmt, int ind,
	const char *label, const uint8_t *d, size_t dlen);
int tls_ctx_enable_signed_certificate_timestamp(TLS_CTX *ctx);
int tls_enable_signed_certificate_timestamp(TLS_CONNECT *conn);

// 41. pre_shared_key
int tls13_psk_identity_to_bytes(const uint8_t *ticket, size_t ticketlen, uint32_t obfuscated_ticket_age,
	uint8_t **out, size_t *outlen);
int tls13_psk_identity_from_bytes(const uint8_t **ticket, size_t *ticketlen, uint32_t *obfuscated_ticket_age,
	const uint8_t **in, size_t *inlen);

int tls13_psk_binders_generate_empty(const int *psk_cipher_suites, size_t psk_cipher_suites_cnt,
	uint8_t *binders, size_t *binders_len);
int tls13_psk_binders_generate(
	const int *psk_cipher_suites, size_t psk_cipher_suites_cnt,
	const uint8_t *psk_keys, size_t psk_keys_len,
	const uint8_t *truncated_client_hello, size_t truncated_client_hello_len,
	uint8_t *binders, size_t *binders_len);
int tls13_psk_binder_verify(const DIGEST *digest,
	const uint8_t *pre_shared_key, size_t pre_shared_key_len,
	const DIGEST_CTX *truncated_client_hello_dgst_ctx,
	const uint8_t *binder, size_t binderlen);
//	ClientHello.exts.pre_shared_key
int tls13_client_pre_shared_key_ext_to_bytes(const uint8_t *identities, size_t identitieslen,
	const uint8_t *binders, size_t binderslen, uint8_t **out, size_t *outlen);
int tls13_client_pre_shared_key_from_bytes(const uint8_t **identities, size_t *identitieslen,
	const uint8_t **binders, size_t *binderslen, const uint8_t *ext_data, size_t ext_datalen);
int tls13_client_pre_shared_key_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen);
//	ServerHello.exts.pre_shared_key
int tls13_server_pre_shared_key_ext_to_bytes(int selected_identity, uint8_t **out, size_t *outlen);
int tls13_server_pre_shared_key_from_bytes(int *selected_identity, const uint8_t *ext_data, size_t ext_datalen);
int tls13_server_pre_shared_key_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen);
int tls13_add_pre_shared_key(TLS_CONNECT *conn,
	const uint8_t *psk_identity, size_t psk_identity_len,
	const uint8_t *psk_key, size_t psk_key_len,
	int psk_cipher_suite, uint32_t obfuscated_ticket_age);
int tls13_process_client_pre_shared_key_external(TLS_CONNECT *conn,
	const uint8_t *ext_data, size_t ext_datalen);
int tls13_process_client_pre_shared_key_from_ticket(TLS_CONNECT *conn,
	const uint8_t *ext_data, size_t ext_datalen);
int tls13_enable_pre_shared_key(TLS_CONNECT *conn, int enable);

// 42. early_data
int tls13_early_data_ext_to_bytes(size_t max_early_data_size, uint8_t **out, size_t *outlen);
int tls13_early_data_from_bytes(size_t *max_early_data_size, const uint8_t *ext_data, size_t ext_datalen);
int tls13_early_data_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen);
int tls13_set_early_data(TLS_CONNECT *conn, const uint8_t *data, size_t datalen);
int tls13_enable_early_data(TLS_CONNECT *conn, int enable);
int tls13_ctx_set_max_early_data_size(TLS_CTX *ctx, size_t max_early_data_size);
int tls13_set_max_early_data_size(TLS_CONNECT *conn, size_t max_early_data_size);

// 43. supported_versions
int tls13_client_supported_versions_ext_to_bytes(const int *versions, size_t versions_cnt,
	uint8_t **out, size_t *outlen);
int tls13_process_client_supported_versions(const uint8_t *ext_data, size_t ext_datalen,
	const int *server_versions, size_t server_versions_cnt,
	int *common_versions, size_t *common_versions_cnt, size_t max_cnt);
int tls13_client_supported_versions_print(FILE *fp, int fmt, int ind,
	const uint8_t *ext_data, size_t ext_datalen);
int tls13_server_supported_versions_ext_to_bytes(int selected_version, uint8_t **out, size_t *outlen);
int tls13_server_supported_versions_from_bytes(int *selected_version, const uint8_t *ext_data, size_t ext_datalen);
int tls13_process_server_supported_versions(const int *client_versions, size_t client_versions_cnt,
	const uint8_t *server_ext_data, size_t server_ext_datalen,
	int *selected_version);
int tls13_server_supported_versions_print(FILE *fp, int fmt, int ind,
	const uint8_t *ext_data, size_t ext_datalen);

int tls13_supported_versions_ext_print(FILE *fp, int fmt, int ind, int handshake_type, const uint8_t *data, size_t datalen);

// 44. cookie
int tls13_cookie_generate(const SM4_KEY *cookie_key, // server_ctx->cookie_key
	const uint8_t *client_info, size_t client_info_len,
	uint8_t *cookie, size_t *cookie_len);
int tls13_cookie_verify(const SM4_KEY *cookie_key, // server_ctx->cookie_key
	const uint8_t *client_info, size_t client_info_len,
	const uint8_t *cookie, size_t cookie_len);
int tls13_cookie_ext_to_bytes(const uint8_t *cookie, size_t cookielen, uint8_t **out, size_t *outlen);
int tls13_cookie_from_bytes(const uint8_t **cookie, size_t *cookielen, const uint8_t *ext_data, size_t ext_datalen);
int tls13_cookie_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen);
int tls13_ctx_set_cookie_key(TLS_CTX *ctx, const uint8_t *cookie_key, size_t cookie_key_len);


// 46. psk_key_exchange_modes

enum {
	TLS_psk_ke		= 0,
	TLS_psk_dhe_ke		= 1,
	TLS_psk_preserved_max	= 255,
};

#define TLS_KE_CERT_DHE		1
#define TLS_KE_PSK_DHE		2
#define TLS_KE_PSK		4

const char *tls13_psk_key_exchange_mode_name(int mode);
int tls13_psk_key_exchange_modes_ext_to_bytes(int modes, uint8_t **out, size_t *outlen);
int tls13_psk_key_exchange_modes_from_bytes(int *modes, const uint8_t *ext_data, size_t ext_datalen);
int tls13_psk_key_exchange_modes_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen);
int tls13_ctx_set_psk_key_exchange_modes(TLS_CTX *ctx, int psk_ke, int psk_dhe_ke);


// 50. signature_algorithms_cert
int tls13_signature_algorithms_cert_ext_to_bytes(const int *algs, size_t algs_cnt,
	uint8_t **out, size_t *outlen);
int tls13_signature_algorithms_cert_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen);
// 用这个处理，tls_process_signature_algorithms


// 51. key_share
int tls13_key_share_entry_to_bytes(const X509_KEY *key, uint8_t **out, size_t *outlen);
int tls13_key_share_entry_from_bytes(int *group, const uint8_t **key_exchange, size_t *key_exchange_len,
	const uint8_t **in, size_t *inlen);
int tls13_key_share_client_hello_ext_to_bytes(const X509_KEY *keys, size_t keys_cnt, uint8_t **out, size_t *outlen);
int tls13_process_key_share_client_hello(const uint8_t *ext_data, size_t ext_datalen,
	const int *common_groups, size_t common_groups_cnt,
	int *group, const uint8_t **key_exchange, size_t *key_exchange_len);
int tls13_key_share_client_hello_print(FILE *fp, int fmt, int ind,
	const uint8_t *data, size_t datalen);
int tls13_key_share_server_hello_ext_to_bytes(const X509_KEY *key, uint8_t **out, size_t *outlen);
int tls13_key_share_server_hello_from_bytes(int *group, const uint8_t **key_exchange, size_t *key_exchange_len,
	const uint8_t *ext_data, size_t ext_datalen);
int tls13_key_share_server_hello_print(FILE *fp, int fmt, int ind,
	const uint8_t *data, size_t datalen);

int tls13_ctx_set_max_key_exchanges(TLS_CTX *ctx, size_t cnt);




#ifdef  __cplusplus
}
#endif
#endif
