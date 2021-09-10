/*
 * Copyright (c) 2020 - 2021 The GmSSL Project.  All rights reserved.
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


#ifndef GMSSL_TLS_H
#define GMSSL_TLS_H


#include <stdint.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/digest.h>
#include <gmssl/block_cipher.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t uint24_t;

void tls_uint8_to_bytes(uint8_t a, uint8_t **out, size_t *outlen);
void tls_uint16_to_bytes(uint16_t a, uint8_t **out, size_t *outlen);
void tls_uint24_to_bytes(uint24_t a, uint8_t **out, size_t *outlen);
void tls_uint32_to_bytes(uint32_t a, uint8_t **out, size_t *outlen);
void tls_array_to_bytes(const uint8_t *data, size_t len, uint8_t **out, size_t *outlen);
void tls_uint8array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
void tls_uint16array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
void tls_uint24array_to_bytes(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
int tls_uint8_from_bytes(uint8_t *a, const uint8_t **in, size_t *inlen);
int tls_uint16_from_bytes(uint16_t *a, const uint8_t **in, size_t *inlen);
int tls_uint24_from_bytes(uint24_t *a, const uint8_t **in, size_t *inlen);
int tls_uint32_from_bytes(uint32_t *a, const uint8_t **in, size_t *inlen);
int tls_array_from_bytes(const uint8_t **data, size_t datalen, const uint8_t **in, size_t *inlen);
int tls_uint8array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_uint16array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_uint24array_from_bytes(const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);
int tls_array_copy_from_bytes(uint8_t *data, size_t datalen, const uint8_t **in, size_t *inlen);
int tls_uint8array_copy_from_bytes(uint8_t *data, size_t *datalen, size_t maxlen, const uint8_t **in, size_t *inlen);
int tls_uint16array_copy_from_bytes(uint8_t *data, size_t *datalen, size_t maxlen, const uint8_t **in, size_t *inlen);
int tls_uint24array_copy_from_bytes(uint8_t *data, size_t *datalen, size_t maxlen, const uint8_t **in, size_t *inlen);


#define TLCP_VERSION_MAJOR 1
#define TLCP_VERSION_MINOR 1


typedef enum {
	TLS_version_tls12_major = 3,
	TLS_version_tls12_minor = 3,
	TLS_version_tlcp	= 0x0101,
	TLS_version_ssl2	= 0x0200,
	TLS_version_ssl3	= 0x0300,
	TLS_version_tls1	= 0x0301,
	TLS_version_tls11	= 0x0302,
	TLS_version_tls12	= 0x0303,
	TLS_version_tls13	= 0x0304,
	TLS_version_dtls1	= 0xfeff, // {254, 255}
	TLS_version_dtls12	= 0xfefd, // {254, 253}
} TLS_VERSION;

typedef enum {
	TLS_cipher_null_with_null_null		= 0x0000,
	TLS_cipher_sm4_gcm_sm3			= 0x00c6,
	TLS_cipher_sm4_ccm_sm3			= 0x00c7,
	TLCP_cipher_ecdhe_sm4_cbc_sm3		= 0xe011, // TLCP, TLS 1.2
	TLCP_cipher_ecdhe_sm4_gcm_sm3		= 0xe051,
	TLCP_cipher_ecc_sm4_cbc_sm3		= 0xe013,
	TLCP_cipher_ecc_sm4_gcm_sm3		= 0xe053,
	TLCP_cipher_ibsdh_sm4_cbc_sm3		= 0xe015,
	TLCP_cipher_ibsdh_sm4_gcm_sm3		= 0xe055,
	TLCP_cipher_ibc_sm4_cbc_sm3		= 0xe017,
	TLCP_cipher_ibc_sm4_gcm_sm3		= 0xe057,
	TLCP_cipher_rsa_sm4_cbc_sm3		= 0xe019,
	TLCP_cipher_rsa_sm4_gcm_sm3		= 0xe059,
	TLCP_cipher_rsa_sm4_cbc_sha256		= 0xe01c,
	TLCP_cipher_rsa_sm4_gcm_sha256		= 0xe05a,
	GMSSL_cipher_ecdhe_sm2_with_sm4_sm3	= 0xe102,
	GMSSL_cipher_ecdhe_sm2_with_sm4_gcm_sm3	= 0xe107,
	GMSSL_cipher_ecdhe_sm2_with_sm4_ccm_sm3	= 0xe108,
	GMSSL_cipher_ecdhe_sm2_with_zuc_sm3	= 0xe10d,
	TLS_cipher_empty_renegotiation_info_scsv = 0x00ff,

	// TLS 1.3 ciphers (rfc 8446 p.133)
	TLS_cipher_aes_128_gcm_sha256		= 0x1301, // mandatory-to-implement
	TLS_cipher_aes_256_gcm_sha384		= 0x1302, // SHOULD implement
	TLS_cipher_chacha20_poly1305_sha256	= 0x1303, // SHOULD implement
	TLS_cipher_aes_128_ccm_sha256		= 0x1304,
	TLS_cipher_aes_128_ccm_8_sha256		= 0x1305,

} TLS_CIPHER_SUITE;

typedef enum {
	TLS_record_invalid		= 0, // TLS 1.3
	TLS_record_change_cipher_spec	= 20,
	TLS_record_alert		= 21,
	TLS_record_handshake		= 22,
	TLS_record_application_data	= 23,
	TLS_record_heartbeat		= 24,
	TLS_record_tls12_cid		= 25,
} TLS_RECORD_TYPE;

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

typedef enum {
	TLS_compression_null	= 0,
	TLS_compression_default	= 1,
} TLS_COMPRESSION_METHOD;

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

typedef enum {
	TLS_extension_server_name		= 0, // tls 1.3 mandatory-to-implement
	TLS_extension_max_fragment_length	= 1,
	TLS_extension_client_certificate_url	= 2,
	TLS_extension_trusted_ca_keys		= 3,
	TLS_extension_truncated_hmac		= 4,
	TLS_extension_status_request		= 5,
	TLS_extension_user_mapping		= 6,
	TLS_extension_client_authz		= 7,
	TLS_extension_server_authz		= 8,
	TLS_extension_cert_type			= 9,  // 这个是支持服务器证书的类型吗？仅仅用CIPHER_SUITE不够吗？
	TLS_extension_supported_groups		= 10, // 必须支持
	TLS_extension_ec_point_formats		= 11, // 必须支持
	TLS_extension_srp			= 12,
	TLS_extension_signature_algorithms	= 13, // // tls 1.3 mandatory-to-implement
	TLS_extension_use_srtp			= 14,
	TLS_extension_heartbeat			= 15,
	TLS_extension_application_layer_protocol_negotiation= 16,
	TLS_extension_status_request_v2		= 17,
	TLS_extension_signed_certificate_timestamp = 18,
	TLS_extension_client_certificate_type	= 19,
	TLS_extension_server_certificate_type	= 20,
	TLS_extension_padding			= 21,
	TLS_extension_encrypt_then_mac		= 22, // 应该支持
	TLS_extension_extended_master_secret	= 23, // 这个是什么意思？
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
	TLS_extension_session_ticket		= 35, // 应该支持
	TLS_extension_TLMSP			= 36,
	TLS_extension_TLMSP_proxying		= 37,
	TLS_extension_TLMSP_delegate		= 38,
	TLS_extension_supported_ekt_ciphers	= 39,
	TLS_extension_pre_shared_key		= 41,
	TLS_extension_early_data		= 42,
	TLS_extension_supported_versions	= 43, // tls 1.3 mandatory-to-implement
	TLS_extension_cookie			= 44, // tls 1.3 mandatory-to-implement
	TLS_extension_psk_key_exchange_modes	= 46,
	TLS_extension_certificate_authorities	= 47,
	TLS_extension_oid_filters		= 48,
	TLS_extension_post_handshake_auth	= 49,
	TLS_extension_signature_algorithms_cert	= 50, // tls 1.3 mandatory-to-implement
	TLS_extension_key_share			= 51,
	TLS_extension_transparency_info		= 52,
	TLS_extension_connection_id		= 53,
	TLS_extension_external_id_hash		= 55,
	TLS_extension_external_session_id	= 56,
	TLS_extension_quic_transport_parameters	= 57,
	TLS_extension_ticket_request		= 58,
	TLS_extension_renegotiation_info	= 65281,
} TLS_EXTENSION_TYPE;

typedef enum {
	TLS_point_uncompressed = 0,
	TLS_point_ansix962_compressed_prime = 1,
	TLS_point_ansix962_compressed_char2 = 2,
} TLS_EC_POINT_FORMAT;

typedef enum {
	TLS_curve_type_explicit_prime	= 1,
	TLS_curve_type_explicit_char2	= 2,
	TLS_curve_type_named_curve	= 3,
} TLS_CURVE_TYPE;

typedef enum {
	TLS_curve_secp256k1		= 22,
	TLS_curve_secp256r1		= 23,
	TLS_curve_secp384r1		= 24,
	TLS_curve_secp521r1		= 25,
	TLS_curve_brainpoolp256r1	= 26,
	TLS_curve_brainpoolp384r1	= 27,
	TLS_curve_brainpoolp512r1	= 28,
	TLS_curve_x25519		= 29,
	TLS_curve_x448			= 99, //30,
	TLS_curve_brainpoolp256r1tls13	= 31,
	TLS_curve_brainpoolp384r1tls13	= 32,
	TLS_curve_brainpoolp512r1tls13	= 33,
	TLS_curve_sm2p256v1		= 30,//41, // in gmssl v2, is 30
} TLS_NAMED_CURVE;

typedef enum {
	TLS_sig_rsa_pkcs1_sha1		= 0x0201,
	TLS_sig_ecdsa_sha1		= 0x0203,
	TLS_sig_rsa_pkcs1_sha256	= 0x0401,
	TLS_sig_ecdsa_secp256r1_sha256	= 0x0403,
	TLS_sig_rsa_pkcs1_sha256_legacy	= 0x0420,
	TLS_sig_rsa_pkcs1_sha384	= 0x0501,
	TLS_sig_ecdsa_secp384r1_sha384	= 0x0503,
	TLS_sig_rsa_pkcs1_sha384_legacy	= 0x0520,
	TLS_sig_rsa_pkcs1_sha512	= 0x0601,
	TLS_sig_ecdsa_secp521r1_sha512	= 0x0603,
	TLS_sig_rsa_pkcs1_sha512_legacy	= 0x0620,
	TLS_sig_sm2sig_sm3		= 0x0707,//0x0708, // is 0707 in gmsslv2
	TLS_sig_rsa_pss_rsae_sha256	= 0x0804,
	TLS_sig_rsa_pss_rsae_sha384	= 0x0805,
	TLS_sig_rsa_pss_rsae_sha512	= 0x0806,
	TLS_sig_ed25519			= 0x0807,
	TLS_sig_ed448			= 0x0808,
	TLS_sig_rsa_pss_pss_sha256	= 0x0809,
	TLS_sig_rsa_pss_pss_sha384	= 0x080A,
	TLS_sig_rsa_pss_pss_sha512	= 0x080B,
	TLS_sig_ecdsa_brainpoolP256r1tls13_sha256 = 0x081A,
	TLS_sig_ecdsa_brainpoolP384r1tls13_sha384 = 0x081B,
	TLS_sig_ecdsa_brainpoolP512r1tls13_sha512 = 0x081C,
} TLS_SIGNATURE_SCHEME;

typedef enum {
	TLS_change_cipher_spec = 1,
} TLS_CHANGE_CIPHER_SPEC_TYPE;

typedef enum {
	TLS_alert_level_warning = 1,
	TLS_alert_level_fatal = 2,
} TLS_ALERT_LEVEL;

typedef enum {
	TLS_alert_close_notify		= 0,
	TLS_alert_unexpected_message	= 10,
	TLS_alert_bad_record_mac	= 20,
	TLS_alert_decryption_failed	= 21,
	TLS_alert_record_overflow	= 22,
	TLS_alert_decompression_failure	= 30,
	TLS_alert_handshake_failure	= 40,
	TLS_alert_no_certificate	= 41,
	TLS_alert_bad_certificate	= 42,
	TLS_alert_unsupported_certificate = 43,
	TLS_alert_certificate_revoked	= 44,
	TLS_alert_certificate_expired	= 45,
	TLS_alert_certificate_unknown	= 46,
	TLS_alert_illegal_parameter	= 47,
	TLS_alert_unknown_ca		= 48,
	TLS_alert_access_denied		= 49,
	TLS_alert_decode_error		= 50,
	TLS_alert_decrypt_error		= 51,
	TLS_alert_export_restriction	= 60,
	TLS_alert_protocol_version	= 70,
	TLS_alert_insufficient_security	= 71,
	TLS_alert_internal_error	= 80,
	TLS_alert_user_canceled		= 90,
	TLS_alert_no_renegotiation	= 100,
	TLS_alert_unsupported_site2site	= 200,
	TLS_alert_no_area		= 201,
	TLS_alert_unsupported_areatype	= 202,
	TLS_alert_bad_ibcparam		= 203,
	TLS_alert_unsupported_ibcparam	= 204,
	TLS_alert_identity_need		= 205,
} TLS_ALERT_DESCRIPTION;




#define TLS_RECORD_MAX_PLAINDATA_SIZE	16384 // 2^14
#define TLS_RECORD_MAX_DATA_SIZE	18432 // 2^24 + 2048
#define TLS_RECORD_MAX_SIZE		18437 // 5 + (2^24 + 2048)

#define TLS_MAX_RECORD_SIZE		18437 // 5 + (2^24 + 2048)

#define TLS_MAX_SIGNATURE_SIZE		SM2_MAX_SIGNATURE_SIZE

#define TLS_MAX_EXTENSIONS_SIZE		512
#define TLS_MAX_CERT_SIZE		1024
#define TLS_MAX_CERTIFICATES_SIZE	2048
#define TLS_MAX_SERVER_CERTS_SIZE	2048

#define TLS_MAX_HANDSHAKES_SIZE		4096


// 应该保留对方的证书

// 我们应该讲这个值编码为一个标准的TLS的结构


typedef struct {
	int is_client;
	int version;
	int cipher_suite;
	int compression_method;
	uint8_t master_secret[48];
	uint8_t server_certs[1600];
	size_t server_certs_size;
	uint8_t client_cert[1024];
	size_t client_cert_size;
} TLS_SESSION;


typedef struct {
	int sock;
	int is_client;
	int version;
	int cipher_suite;
	uint8_t session_id[32];
	size_t session_id_len;
	uint8_t master_secret[48];
	uint8_t key_block[96];
	int do_trace;

	uint8_t server_certs[TLS_MAX_CERTIFICATES_SIZE];
	size_t server_certs_len;

	uint8_t client_certs[TLS_MAX_CERTIFICATES_SIZE];
	size_t client_certs_len;

	SM3_HMAC_CTX client_write_mac_ctx;
	SM3_HMAC_CTX server_write_mac_ctx;
	SM4_KEY client_write_enc_key;
	SM4_KEY server_write_enc_key;
	uint8_t client_seq_num[8];
	uint8_t server_seq_num[8];

	uint8_t record[TLS_MAX_RECORD_SIZE];
	uint8_t handshakes[TLS_MAX_HANDSHAKES_SIZE];
	size_t handshakes_len;

	uint8_t client_write_iv[12];
	uint8_t server_write_iv[12];



	BLOCK_CIPHER_KEY client_write_key;
	BLOCK_CIPHER_KEY server_write_key;

} TLS_CONNECT;
















// 有可能在连接建立之后，客户端还是想获得一些这个连接的有关信息呢？比如random中有时间信息？
// 服务器的证书一定是需要的吧


// 客户端证书应该是预置的
int tlcp_connect(TLS_CONNECT *conn, const char *hostname, int port,
	FILE *ca_certs_fp, FILE *client_certs_fp, const SM2_KEY *client_sign_key);

int tlcp_accept(TLS_CONNECT *conn, int port,
	FILE *server_certs_fp, const SM2_KEY *server_sign_key, const SM2_KEY *server_enc_key,
	FILE *client_cacerts_fp, uint8_t *client_cert_verify_buf, size_t client_cert_verify_buflen);


int tls_send(TLS_CONNECT *conn, const uint8_t *data, size_t datalen);
int tls_recv(TLS_CONNECT *conn, uint8_t *data, size_t *datalen);



int tls_seq_num_incr(uint8_t seq_num[8]);


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


const char *tls_record_type_name(int type);
int tls_record_version(const uint8_t *record);
int tls_record_length(const uint8_t *record);

const char *tls_version_text(int version);

int tls_record_set_version(uint8_t *record, int version);


int tls_record_encrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *cbc_key,
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);
int tls_record_decrypt(const SM3_HMAC_CTX *hmac_ctx, const SM4_KEY *cbc_key,
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);


int tls_record_send(const uint8_t *record, size_t recordlen, int sock);
int tls_record_recv(uint8_t *record, size_t *recordlen, int sock);


int tls_random_generate(uint8_t random[32]);
int tls_random_print(FILE *fp, const uint8_t random[32], int format, int indent);
int tls_pre_master_secret_generate(uint8_t pre_master_secret[48], int version);
int tls_pre_master_secret_print(FILE *fp, const uint8_t pre_master_secret[48], int format, int indent);


int tls_cipher_suite_in_list(int cipher, const int *list, size_t list_count);
const char *tlcp_cipher_suite_name(int cipher);
const char *tls_cipher_suite_name(int cipher);
const char *tls_compression_method_name(int meth);


int tls_record_set_handshake(uint8_t *record, size_t *recordlen,
	int type, const uint8_t *data, size_t datalen);
int tls_record_get_handshake(const uint8_t *record,
	int *type, const uint8_t **data, size_t *datalen);


int tls_record_set_handshake_client_hello(uint8_t *record, size_t *recordlen,
	int client_version, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len,
	const int *cipher_suites, size_t cipher_suites_count,
	const uint8_t *exts, size_t exts_len);

int tls_record_get_handshake_client_hello(const uint8_t *record,
	int *client_version, uint8_t random[32],
	uint8_t *session_id, size_t *session_id_len,
	int *cipher_suites, size_t *cipher_suites_count,
	uint8_t *exts, size_t *exts_len);

int tls_client_hello_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);

int tls_record_set_handshake_server_hello(uint8_t *record, size_t *recordlen,
	int server_version, const uint8_t random[32],
	const uint8_t *session_id, size_t session_id_len, int cipher_suite,
	const uint8_t *exts, size_t exts_len);

int tls_record_get_handshake_server_hello(const uint8_t *record,
	int *version, uint8_t random[32], uint8_t *session_id, size_t *session_id_len,
	int *cipher_suite, uint8_t *exts, size_t *exts_len);

int tls_server_hello_print(FILE *fp, const uint8_t *server_hello, size_t len, int format, int indent);

int tls_record_set_handshake_certificate(uint8_t *record, size_t *recordlen,
	const uint8_t *certs, size_t certslen);
int tls_record_set_handshake_certificate_from_pem(uint8_t *record, size_t *recordlen, FILE *fp);
int tls_record_get_handshake_certificate(const uint8_t *record, uint8_t *certs, size_t *certslen);
int tls_certificate_get_subject_names(const uint8_t *certs, size_t certslen, uint8_t *names, size_t *nameslen);
int tls_certificate_get_public_keys(const uint8_t *certs, size_t certslen, SM2_KEY *sign_key, SM2_KEY *enc_key);
int tls_certificate_print(FILE *fp, const uint8_t *certs, size_t certslen, int format, int indent);

int tls_certificate_chain_verify(const uint8_t *certs, size_t certslen, FILE *ca_certs_fp, int depth);

int tls_certificate_get_first(const uint8_t *data, size_t datalen, const uint8_t **cert, size_t *certlen);
int tls_certificate_get_second(const uint8_t *data, size_t datalen, const uint8_t **cert, size_t *certlen);


// 应该把所有TLCP协议的内容放到一起
int tlcp_record_set_handshake_server_key_exchange_pke(uint8_t *record, size_t *recordlen,
	const uint8_t *sig, size_t siglen);
int tlcp_record_get_handshake_server_key_exchange_pke(const uint8_t *record,
	uint8_t *sig, size_t *siglen);
int tlcp_server_key_exchange_pke_print(FILE *fp, const uint8_t *sig, size_t siglen, int format, int indent);



int tls_server_key_exchange_print(FILE *fp, const uint8_t *ske, size_t skelen, int format, int indent);
const char *tls_cert_type_name(int type);


#define TLS_MAX_CERTIFICATE_TYPES 16
#define TLS_MAX_CA_NAMES_SIZE  256


int tls_record_set_handshake_certificate_request(uint8_t *record, size_t *recordlen,
	const int *cert_types, size_t cert_types_count,
	const uint8_t *ca_names, size_t ca_names_len);

int tls_record_get_handshake_certificate_request(const uint8_t *record,
	int *cert_types, size_t *cert_types_count,
	uint8_t *ca_names, size_t *ca_names_len);



int tls_certificate_request_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);
int tls_record_set_handshake_server_hello_done(uint8_t *record, size_t *recordlen);
int tls_record_get_handshake_server_hello_done(const uint8_t *record);
int tls_server_hello_done_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);

int tls_record_set_handshake_client_key_exchange_pke(uint8_t *record, size_t *recordlen,
	const uint8_t *enced_pms, size_t enced_pms_len);
int tls_record_get_handshake_client_key_exchange_pke(const uint8_t *record,
	uint8_t *enced_pms, size_t *enced_pms_len);
int tls_client_key_exchange_pke_print(FILE *fp, const uint8_t *cke, size_t ckelen, int format, int indent);
int tls_client_key_exchange_print(FILE *fp, const uint8_t *cke, size_t ckelen, int format, int indent);
int tls_record_set_handshake_certificate_verify(uint8_t *record, size_t *recordlen,
	const uint8_t *sig, size_t siglen);
int tls_record_get_handshake_certificate_verify(const uint8_t *record,
	uint8_t *sig, size_t *siglen);
int tls_certificate_verify_print(FILE *fp, const uint8_t *p, size_t len, int format, int indent);

int tls_record_set_handshake_finished(uint8_t *record, size_t *recordlen,
	const uint8_t verify_data[12]);
int tls_record_get_handshake_finished(const uint8_t *record, uint8_t verify_data[12]);
int tls_finished_print(FILE *fp, const uint8_t *a, size_t len, int format, int indent);
const char *tls_handshake_type_name(int type);
int tls_handshake_print(FILE *fp, const uint8_t *handshake, size_t handshakelen, int format, int indent);


const char *tls_alert_level_name(int level);
const char *tls_alert_description_text(int description);
int tls_alert_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);


int tls_record_set_alert(uint8_t *record, size_t *recordlen,
	int alert_level,
	int alert_description);
int tls_record_get_alert(const uint8_t *record,
	int *alert_level,
	int *alert_description);

const char *tls_change_cipher_spec_text(int change_cipher_spec);
int tls_record_set_change_cipher_spec(uint8_t *record, size_t *recordlen);
int tls_record_get_change_cipher_spec(const uint8_t *record);
int tls_change_cipher_spec_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);

int tls_record_set_application_data(uint8_t *record, size_t *recordlen,
	const uint8_t *data, size_t datalen);
int tls_record_get_application_data(uint8_t *record,
	const uint8_t **data, size_t *datalen);
int tls_application_data_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);


int tls_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent);



const char *tls_ec_point_format_name(int format);
const char *tls_curve_type_name(int type);
const char *tls_named_curve_name(int curve);
const char *tls_signature_scheme_name(int scheme);
int tls_sign_server_ecdh_params(const SM2_KEY *server_sign_key,
	const uint8_t client_random[32], const uint8_t server_random[32],
	int curve, const SM2_POINT *point, uint8_t *sig, size_t *siglen);
int tls_verify_server_ecdh_params(const SM2_KEY *server_sign_key,
	const uint8_t client_random[32], const uint8_t server_random[32],
	int curve, const SM2_POINT *point, const uint8_t *sig, size_t siglen);
int tls_record_set_handshake_server_key_exchange_ecdhe(uint8_t *record, size_t *recordlen,
	int curve, const SM2_POINT *point, const uint8_t *sig, size_t siglen);
int tls_record_get_handshake_server_key_exchange_ecdhe(const uint8_t *record,
	int *curve, SM2_POINT *point, uint8_t *sig, size_t *siglen);
int tls_server_key_exchange_ecdhe_print(FILE *fp, const uint8_t *data, size_t datalen,
	int format, int indent);
int tls_record_set_handshake_client_key_exchange_ecdhe(uint8_t *record, size_t *recordlen,
	const SM2_POINT *point);
int tls_record_get_handshake_client_key_exchange_ecdhe(const uint8_t *record, SM2_POINT *point);
int tls_client_key_exchange_ecdhe_print(FILE *fp, const uint8_t *data, size_t datalen,
	int format, int indent);


int tls12_record_recv(uint8_t *record, size_t *recordlen, int sock);


int tls12_connect(TLS_CONNECT *conn, const char *hostname, int port,
	FILE *ca_certs_fp, FILE *client_certs_fp, const SM2_KEY *client_sign_key);

int tls12_accept(TLS_CONNECT *conn, int port,
	FILE *certs_fp, const SM2_KEY *server_sign_key,
	FILE *client_cacerts_fp, uint8_t *handshakes_buf, size_t handshakes_buflen);





int tls13_connect(TLS_CONNECT *conn, const char *hostname, int port,
	FILE *ca_certs_fp, FILE *client_certs_fp, const SM2_KEY *client_sign_key);


int tls13_accept(TLS_CONNECT *conn, int port,
	FILE *certs_fp, const SM2_KEY *server_sign_key,
	FILE *client_cacerts_fp);


int tls_secrets_print(FILE *fp,
	const uint8_t *pre_master_secret, size_t pre_master_secret_len,
	const uint8_t client_random[32], const uint8_t server_random[32],
	const uint8_t master_secret[48],
	const uint8_t *key_block, size_t key_block_len,
	int format, int indent);



int tls_ext_signature_algors_to_bytes(const int *algors, size_t algors_count,
	uint8_t **out, size_t *outlen);

int tls13_send(TLS_CONNECT *conn, const uint8_t *data, size_t datalen, size_t padding_len);
int tls13_recv(TLS_CONNECT *conn, uint8_t *data, size_t *datalen);


int tls13_hkdf_extract(const DIGEST *digest, const uint8_t salt[32], const uint8_t in[32], uint8_t out[32]);
int tls13_hkdf_expand_label(const DIGEST *digest, const uint8_t secret[32],
	const char *label, const uint8_t *context, size_t context_len,
	size_t outlen, uint8_t *out);
int tls13_derive_secret(const uint8_t secret[32], const char *label, const DIGEST_CTX *dgst_ctx, uint8_t out[32]);



int tls_shutdown(TLS_CONNECT *conn);


#define tls_trace printf


#ifdef  __cplusplus
}
#endif
#endif
