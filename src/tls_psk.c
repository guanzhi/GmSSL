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
psk_key_exchange_modes

enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;

struct {
	PskKeyExchangeMode ke_modes<1..255>;
} PskKeyExchangeModes;

*/

const char *tls13_psk_key_exchange_mode_name(int mode)
{
	switch (mode) {
	case TLS_psk_ke: return "psk_ke";
	case TLS_psk_dhe_ke: return "psk_dhe_ke";
	}
	return NULL;
}

int tls13_psk_key_exchange_modes_ext_to_bytes(int modes, uint8_t **out, size_t *outlen)
{
	int type = TLS_extension_psk_key_exchange_modes;
	uint8_t ke_modes[2] = { TLS_psk_dhe_ke, TLS_psk_ke };
	uint8_t ext_data[3];
	uint8_t *p = ext_data;
	size_t ext_datalen = 0;

	if ((modes & TLS_KE_PSK_DHE) && (modes & TLS_KE_PSK)) {
		tls_uint8array_to_bytes(ke_modes, 2, &p, &ext_datalen);
	} else if (modes & TLS_KE_PSK_DHE) {
		tls_uint8array_to_bytes(ke_modes, 1, &p, &ext_datalen);
	} else if (modes & TLS_KE_PSK) {
		tls_uint8array_to_bytes(ke_modes + 1, 1, &p, &ext_datalen);
	}

	if (tls_ext_to_bytes(type, ext_data, ext_datalen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_psk_key_exchange_modes_from_bytes(int *modes, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *ke_modes;
	size_t ke_modes_len;

	if (tls_uint8array_from_bytes(&ke_modes, &ke_modes_len, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}

	while (ke_modes_len) {
		uint8_t mode;
		if (tls_uint8_from_bytes(&mode, &ke_modes, &ke_modes_len) != 1) {
			error_print();
			return -1;
		}
		switch (mode) {
		case TLS_psk_ke:
			*modes |= TLS_KE_PSK;
			break;
		case TLS_psk_dhe_ke:
			*modes |= TLS_KE_PSK_DHE;
			break;
		default:
			error_print();
			return -1;
		}
	}

	return 1;
}

int tls13_psk_key_exchange_modes_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *ke_modes;
	size_t ke_modes_len;

	format_print(fp, fmt, ind, "ke_modes\n");
	ind += 4;
	if (tls_uint8array_from_bytes(&ke_modes, &ke_modes_len, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	if (!ke_modes_len) {
		format_print(fp, fmt, ind, "(null)\n");
	}
	while (ke_modes_len) {
		uint8_t mode;
		tls_uint8_from_bytes(&mode, &ke_modes, &ke_modes_len);
		format_print(fp, fmt, ind, "%s (%d)\n", tls13_psk_key_exchange_mode_name(mode), mode);
	}
	if (ext_datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_ctx_set_psk_key_exchange_modes(TLS_CTX *ctx, int psk_ke, int psk_dhe_ke)
{
	ctx->psk_key_exchange_modes = 0;

	if (psk_ke)
		ctx->psk_key_exchange_modes |= TLS_KE_PSK;

	if (psk_dhe_ke)
		ctx->psk_key_exchange_modes |= TLS_KE_PSK_DHE;

	return 1;
}


/*
PSK 功能的关系

							tls13_ctx_set_session_ticket_key
1. 服务器设定ticket_key

2. 服务器设定发送NewSessionTicket，并且设定数量

3. 服务器 send_new_session_ticket

4. 客户端 recv_new_session_ticket

5. 客户端将session保存到文件中

6. 客户端载入session

7. 客户端发送 pre_shared_key, 其中 ticket 来自session

8. 服务器获取 pre_shared_key, 解密ticket，得到PSK

9. 服务器发送 pre_shared_key, 告知客户端选定的密钥编号



基于外部预置PSK

1. 服务器添加PSK

2. 客户端添加PSK

3. 客户端发送pre_shared_key

4. 服务器用PSK去pre_shared_key查找是否有满足的

5. 服务器发送pre_shared_key，告知客户端选定的密钥编号



*/


/*
session_ticket_key

	* server_only
	* server encrypt and send NewSessionTicket
	* server decrypt ClientHello.pre_shared_key
*/
int tls13_ctx_set_session_ticket_key(TLS_CTX *ctx, const uint8_t *key, size_t keylen)
{
	if (!ctx || !key || !keylen) {
		error_print();
		return -1;
	}
	if (ctx->is_client) {
		error_print();
		return -1;
	}
	if (keylen != SM4_KEY_SIZE) {
		error_print();
		return -1;
	}

	sm4_set_encrypt_key(&ctx->_session_ticket_key, key);
	ctx->session_ticket_key = &ctx->_session_ticket_key;

	return 1;
}

#define TLS_MAX_NEW_SESSION_TICKETS 5
int tls13_ctx_enable_new_session_ticket(TLS_CTX *ctx, size_t new_session_ticket_cnt)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (new_session_ticket_cnt > TLS_MAX_NEW_SESSION_TICKETS) {
		error_print();
		return -1;
	}

	ctx->new_session_ticket = (int)new_session_ticket_cnt;

	return 1;
}

/*
NewSessionTicket.ticket = encrypt(ticket_key, plain_ticket)

PlainTicket {
	uint8_t pre_shared_key[32];
	uint16_t protocol_version;
	uint16_t cipher_suite;
	uint32_t ticket_issue_time;
	uint32_t ticket_lifetime;
};
*/
int tls13_ticket_encrypt(const SM4_KEY *key, const uint8_t pre_shared_key[32],
	int protocol_version, int cipher_suite, uint32_t ticket_issue_time,  uint32_t ticket_lifetime,
	uint8_t *out, size_t *outlen)
{
	uint8_t ticket[32 + 2 + 2 + 4 + 4];
	uint8_t *p = ticket;
	size_t ticketlen = 0;

	uint8_t *iv = out;
	size_t ivlen = 12;
	const uint8_t *aad = NULL;
	size_t aadlen = 0;
	uint8_t *tag;
	size_t taglen = 16;

	if (!key || !pre_shared_key || !out || !outlen) {
		error_print();
		return -1;
	}


	out += ivlen;
	tag = out + sizeof(ticket);

	tls_array_to_bytes(pre_shared_key, 32, &p, &ticketlen);
	tls_uint16_to_bytes(protocol_version, &p, &ticketlen);
	tls_uint16_to_bytes(cipher_suite, &p, &ticketlen);
	tls_uint32_to_bytes(ticket_issue_time, &p, &ticketlen);
	tls_uint32_to_bytes(ticket_lifetime, &p, &ticketlen);

	if (ticketlen != sizeof(ticket)) {
		error_print();
		return -1;
	}

	if (rand_bytes(iv, ivlen) != 1) {
		error_print();
		return -1;
	}
	if (sm4_gcm_encrypt(key, iv, ivlen, aad, aadlen, ticket, ticketlen, out, taglen, tag) != 1) {
		error_print();
		return -1;
	}

	*outlen = ivlen + sizeof(ticket) + taglen;
	return 1;
}

int tls13_ticket_decrypt(const SM4_KEY *key, const uint8_t *in, size_t inlen,
	uint8_t pre_shared_key[32], int *protocol_version, int *cipher_suite,
	uint32_t *ticket_issue_time, uint32_t *ticket_lifetime)
{
	const uint8_t *iv;
	size_t ivlen = 12;
	const uint8_t *aad = NULL;
	size_t aadlen = 0;
	const uint8_t *tag;
	size_t taglen = 16;

	uint8_t ticket[32 + 2 + 2 + 4 + 4];
	const uint8_t *cp = ticket;
	const uint8_t *psk;
	uint16_t version;
	uint16_t cipher;

	if (inlen != ivlen + sizeof(ticket) + taglen) {
		error_print();
		return -1;
	}
	iv = in;

	in += ivlen;
	inlen -= ivlen;

	tag = in + sizeof(ticket);
	inlen -= taglen;

	if (sm4_gcm_decrypt(key, iv, ivlen, aad, aadlen, in, sizeof(ticket), tag, taglen, ticket) != 1) {
		error_print();
		return -1;
	}
	if (tls_array_from_bytes(&psk, 32, &cp, &inlen) != 1
		|| tls_uint16_from_bytes(&version, &cp, &inlen) != 1
		|| tls_uint16_from_bytes(&cipher, &cp, &inlen) != 1
		|| tls_uint32_from_bytes(ticket_issue_time, &cp, &inlen) != 1
		|| tls_uint32_from_bytes(ticket_lifetime, &cp, &inlen) != 1
		|| tls_length_is_zero(inlen) != 1) {
		error_print();
		return -1;
	}
	memcpy(pre_shared_key, psk, 32);
	*protocol_version = version;
	*cipher_suite = cipher;
	return 1;
}

int tls13_ticket_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *resumption_master_secret;
	uint16_t protocol_version;
	uint16_t cipher_suite;
	uint32_t ticket_issue_time;
	uint32_t ticket_lifetime;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (tls_array_from_bytes(&resumption_master_secret, 48, &d, &dlen) != 1
		|| tls_uint16_from_bytes(&protocol_version, &d, &dlen) != 1
		|| tls_uint16_from_bytes(&cipher_suite, &d, &dlen) != 1
		|| tls_uint32_from_bytes(&ticket_issue_time, &d, &dlen) != 1
		|| tls_uint32_from_bytes(&ticket_lifetime, &d, &dlen) != 1
		|| tls_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "resumption_master_secret", resumption_master_secret, 48);
	format_print(fp, fmt, ind, "protocol_version: %s (%04x)\n", tls_protocol_name(protocol_version), protocol_version);
	format_print(fp, fmt, ind, "cipher_suite: %s (%04x)\n", tls_cipher_suite_name(cipher_suite), cipher_suite);
	format_print(fp, fmt, ind, "ticket_issue_time: %"PRIu32"\n", ticket_issue_time);
	format_print(fp, fmt, ind, "ticket_lifetime: %"PRIu32"\n", ticket_lifetime);
	return 1;
}


/*
NewSessionTicket

      struct {
          uint32 ticket_lifetime;
          uint32 ticket_age_add;
          opaque ticket_nonce<0..255>;
          opaque ticket<1..2^16-1>;
          Extension extensions<0..2^16-2>;
      } NewSessionTicket;
*/
int tls13_record_set_handshake_new_session_ticket(uint8_t *record, size_t *recordlen,
	uint32_t ticket_lifetime, uint32_t ticket_age_add,
	const uint8_t *ticket_nonce, size_t ticket_nonce_len,
	const uint8_t *ticket, size_t ticketlen,
	const uint8_t *exts, size_t extslen)
{
	int type = TLS_handshake_new_session_ticket;
	uint8_t *p = record + 5 + 4;
	size_t len = 0;

	if (ticket_nonce_len > 255
		|| ticketlen > 65535
		|| extslen > 65534) {
		error_print();
		return -1;
	}
	tls_uint32_to_bytes(ticket_lifetime, &p, &len);
	tls_uint32_to_bytes(ticket_age_add, &p, &len);
	tls_uint8array_to_bytes(ticket_nonce, ticket_nonce_len, &p, &len);
	tls_uint16array_to_bytes(ticket, ticketlen, &p, &len);
	tls_uint16array_to_bytes(exts, extslen, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls13_record_get_handshake_new_session_ticket(uint8_t *record,
	uint32_t *ticket_lifetime, uint32_t *ticket_age_add,
	const uint8_t **ticket_nonce, size_t *ticket_nonce_len,
	const uint8_t **ticket, size_t *ticketlen,
	const uint8_t **exts, size_t *extslen)
{
	int type;
	const uint8_t *cp;
	size_t len;

	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_new_session_ticket) {
		error_print();
		return -1;
	}
	if (tls_uint32_from_bytes(ticket_lifetime, &cp, &len) != 1
		|| tls_uint32_from_bytes(ticket_age_add, &cp, &len) != 1
		|| tls_uint8array_from_bytes(ticket_nonce, ticket_nonce_len, &cp, &len) != 1
		|| tls_uint16array_from_bytes(ticket, ticketlen, &cp, &len) != 1
		|| tls_uint16array_from_bytes(exts, extslen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (*ticket_lifetime > 60 * 60 * 24 * 7) {
		error_print();
		return -1;
	}
	if (!ticketlen) {
		error_print();
		return -1;
	}
	if (*extslen > 65534) {
		error_print();
		return -1;
	}
	return 1;
}

/*
when recv NewSessionTicket, client save session info (psk, ticket, ...)

Session {
	uint16_t protocol_version;
	uint16_t cipher_suite;
	uint8array_t pre_shared_key;
	uint32_t ticket_issue_time;
	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	uint16array_t ticket;
};
*/
int tls13_session_to_bytes(int protocol_version, int cipher_suite,
	const uint8_t *pre_shared_key, size_t pre_shared_key_len,
	uint32_t ticket_issue_time, uint32_t ticket_lifetime, uint32_t ticket_age_add,
	const uint8_t *ticket, size_t ticketlen, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	// 这个写法需要改一下，改为直接输出，最后再更改长度
	tls_uint16_to_bytes((uint16_t)protocol_version, NULL, &len);
	tls_uint16_to_bytes((uint16_t)cipher_suite, NULL, &len);
	tls_uint8array_to_bytes(pre_shared_key, pre_shared_key_len, NULL, &len);
	tls_uint32_to_bytes(ticket_issue_time, NULL, &len);
	tls_uint32_to_bytes(ticket_lifetime, NULL, &len);
	tls_uint32_to_bytes(ticket_age_add, NULL, &len);
	tls_uint16array_to_bytes(ticket, ticketlen, NULL, &len);

	tls_uint16_to_bytes(len, out, outlen);

	tls_uint16_to_bytes((uint16_t)protocol_version, out, outlen);
	tls_uint16_to_bytes((uint16_t)cipher_suite, out, outlen);
	tls_uint8array_to_bytes(pre_shared_key, pre_shared_key_len, out, outlen);
	tls_uint32_to_bytes(ticket_issue_time, out, outlen);
	tls_uint32_to_bytes(ticket_lifetime, out, outlen);
	tls_uint32_to_bytes(ticket_age_add, out, outlen);
	tls_uint16array_to_bytes(ticket, ticketlen, out, outlen);

	return 1;
}

int tls13_session_from_bytes(int *protocol_version, int *cipher_suite,
	const uint8_t **pre_shared_key, size_t *pre_shared_key_len,
	uint32_t *ticket_issue_time, uint32_t *ticket_lifetime, uint32_t *ticket_age_add,
	const uint8_t **ticket, size_t *ticketlen,
	const uint8_t **in, size_t *inlen)
{
	const uint8_t *cp;
	size_t len;
	uint16_t version;
	uint16_t cipher;

	if (tls_uint16array_from_bytes(&cp, &len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&version, &cp, &len) != 1
		|| tls_uint16_from_bytes(&cipher, &cp, &len) != 1
		|| tls_uint8array_from_bytes(pre_shared_key, pre_shared_key_len, &cp, &len) != 1
		|| tls_uint32_from_bytes(ticket_issue_time, &cp, &len) != 1
		|| tls_uint32_from_bytes(ticket_lifetime, &cp, &len) != 1
		|| tls_uint32_from_bytes(ticket_age_add, &cp, &len) != 1
		|| tls_uint16array_from_bytes(ticket, ticketlen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(version)) {
		error_print();
		return -1;
	}
	*protocol_version = version;
	if (!tls_cipher_suite_name(cipher)) {
		error_print();
		return -1;
	}
	*cipher_suite = cipher;
	if (*pre_shared_key_len != 32) {
		error_print();
		return -1;
	}
	if (*ticket_lifetime > 60 * 60 * 24 * 7) {
		error_print();
		return -1;
	}
	if (!ticketlen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_session_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	const uint8_t *cp;
	size_t len;
	uint16_t protocol_version;
	uint16_t cipher_suite;
	const uint8_t *pre_shared_key;
	size_t pre_shared_key_len;
	uint32_t ticket_issue_time;
	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	const uint8_t *ticket;
	size_t ticketlen;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (tls_uint16array_from_bytes(&cp, &len, &a, &alen) != 1) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(&protocol_version, &cp, &len) != 1
		|| tls_uint16_from_bytes(&cipher_suite, &cp, &len) != 1
		|| tls_uint8array_from_bytes(&pre_shared_key, &pre_shared_key_len, &cp, &len) != 1
		|| tls_uint32_from_bytes(&ticket_issue_time, &cp, &len) != 1
		|| tls_uint32_from_bytes(&ticket_lifetime, &cp, &len) != 1
		|| tls_uint32_from_bytes(&ticket_age_add, &cp, &len) != 1
		|| tls_uint16array_from_bytes(&ticket, &ticketlen, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "protocol_version: %s (%04x)\n", tls_protocol_name(protocol_version), protocol_version);
	format_print(fp, fmt, ind, "cipher_suite: %s (%04x)\n", tls_cipher_suite_name(cipher_suite), cipher_suite);
	format_bytes(fp, fmt, ind, "pre_shared_key", pre_shared_key, pre_shared_key_len);
	format_print(fp, fmt, ind, "ticket_issue_time: %"PRIu32"\n", ticket_issue_time);
	format_print(fp, fmt, ind, "ticket_lifetime: %"PRIu32"\n", ticket_lifetime);
	format_print(fp, fmt, ind, "ticket_age_add: %"PRIu32"\n", ticket_age_add);
	format_bytes(fp, fmt, ind, "ticket", ticket, ticketlen);
	if (tls_length_is_zero(alen) != 1 || tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

// client only
int tls13_add_pre_shared_key_from_session_file(TLS_CONNECT *conn, FILE *fp)
{
	int ret;
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;

	int protocol_version;
	int cipher_suite;
	const uint8_t *pre_shared_key;
	size_t pre_shared_key_len;
	uint32_t ticket_issue_time;
	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	const uint8_t *ticket;
	size_t ticketlen;

	uint32_t obfuscated_ticket_age;

	format_print(stderr, 0, 0, "read SESSION\n");

	if ((ret = tls_uint16array_from_file(buf, &len, sizeof(buf), fp)) < 0) {
		error_print();
		return -1;
	} else if (ret == 0) {
		return 0;
	}

	if (tls13_session_from_bytes(&protocol_version, &cipher_suite,
		&pre_shared_key, &pre_shared_key_len,
		&ticket_issue_time, &ticket_lifetime, &ticket_age_add,
		&ticket, &ticketlen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (pre_shared_key_len != 32) {
		error_print();
		return -1;
	}

	if (tls13_add_pre_shared_key(conn, ticket, ticketlen,
		pre_shared_key, pre_shared_key_len, cipher_suite, obfuscated_ticket_age) != 1) {
		error_print();
		return -1;
	}

	conn->pre_shared_key = 1;
	return 1;
}

int tls13_set_session_outfile(TLS_CONNECT *conn, const char *file)
{
	if (!conn || !file) {
		error_print();
		return -1;
	}
	conn->session_out = file;
	return 1;
}

int tls13_send_new_session_ticket(TLS_CONNECT *conn)
{
	int ret;
	size_t padding_len;

	tls_trace("send {NewSessionTicket*}\n");

	if (conn->recordlen == 0) {
		// new_session_ticket
		uint32_t ticket_lifetime = 60 * 60 * 24 * 2; // = 2 days
		uint32_t ticket_age_add;
		uint8_t ticket_nonce[8];
		uint8_t ticket[12 + (32 + 2 + 2 + 4 + 4) + 16];
		size_t ticketlen;
		uint8_t exts[16];
		size_t extslen = 0;
		uint8_t *p = exts;
		// early_data
		uint32_t max_early_data_size = 256 * 1024; // 256 KB
		uint32_t ticket_issue_time = time(NULL);

		if (rand_bytes((uint8_t *)&ticket_age_add, sizeof(ticket_age_add)) != 1) {
			error_print();
			return -1;
		}
		if (rand_bytes(ticket_nonce, sizeof(ticket_nonce)) != 1) {
			error_print();
			return -1;
		}

		uint8_t resumption_master_secret[48];
		size_t dgstlen = 32;
		uint8_t pre_shared_key[32];

		// generate resumption_master_secret
		/* [14] */ tls13_derive_secret(conn->master_secret, "res master", &conn->dgst_ctx, resumption_master_secret);

		// pre_shared_key = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
		tls13_hkdf_expand_label(conn->digest, resumption_master_secret, "resumption",
			ticket_nonce, sizeof(ticket_nonce), dgstlen, pre_shared_key);

		format_bytes(stderr, 0, 0, ">>>> pre_shared_key", pre_shared_key, sizeof(pre_shared_key));

		if (tls13_ticket_encrypt(conn->ctx->session_ticket_key,
			pre_shared_key, conn->protocol, conn->cipher_suite,
			ticket_issue_time, ticket_lifetime, ticket, &ticketlen) != 1) {
			error_print();
			return -1;
		}
		if (ticketlen != sizeof(ticket)) {
			error_print();
			return -1;
		}

		if (tls13_early_data_ext_to_bytes(max_early_data_size, &p, &extslen) != 1) {
			error_print();
			return -1;
		}

		if (tls13_record_set_handshake_new_session_ticket(
			conn->plain_record, &conn->plain_recordlen,
			ticket_lifetime, ticket_age_add,
			ticket_nonce, sizeof(ticket_nonce),
			ticket, ticketlen,
			exts, extslen) != 1) {
			error_print();
			return -1;
		}
		tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_seq_num_incr(conn->server_seq_num);

		conn->new_session_ticket--;
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	return 1;
}

// 这个函数是有点问题的，还是应该改为recv_new_session_ticket
int tls13_process_new_session_ticket(TLS_CONNECT *conn)
{
	int ret;
	/*
	int handshake_type;
	const uint8_t *handshake_data;
	size_t handshake_datalen;
	*/

	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	const uint8_t *ticket_nonce;
	size_t ticket_nonce_len;
	const uint8_t *ticket;
	size_t ticketlen;
	const uint8_t *exts;
	size_t extslen;
	size_t max_early_data_size;
	const uint8_t *cp;
	size_t len;

	// only cheching encoding
	if ((ret = tls13_record_get_handshake_new_session_ticket(conn->plain_record,
		&ticket_lifetime, &ticket_age_add, &ticket_nonce, &ticket_nonce_len,
		&ticket, &ticketlen, &exts, &extslen)) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	}

	if (!ticket_lifetime || ticket_lifetime > 60 * 60 * 24 * 7) {
		error_print();
		return -1;
	}
	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		// exts in NST
		//  * early_data

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}
		switch (ext_type) {
		case TLS_extension_early_data:
			if (tls13_early_data_from_bytes(&max_early_data_size, ext_data, ext_datalen) != 1) {
				error_print();
				return -1;
			}
			break;
		default:
			error_print();
			return -1;
		}
	}

	uint8_t resumption_master_secret[48];
	size_t dgstlen = 32;
	uint8_t pre_shared_key[32];

	// generate resumption_master_secret
	/* [14] */ tls13_derive_secret(conn->master_secret, "res master", &conn->dgst_ctx, resumption_master_secret);

	// pre_shared_key = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
	tls13_hkdf_expand_label(conn->digest, resumption_master_secret, "resumption",
		ticket_nonce, ticket_nonce_len, dgstlen, pre_shared_key);

	uint8_t session[512];
	uint8_t *p = session;
	size_t sessionlen = 0;

	uint32_t ticket_issue_time = time(NULL);

	if (tls13_session_to_bytes(conn->protocol, conn->cipher_suite, pre_shared_key, 32,
		ticket_issue_time, ticket_lifetime, ticket_age_add, ticket, ticketlen,
		&p, &sessionlen) != 1) {
		error_print();
		return -1;
	}
	tls13_session_print(stderr, 0, 0, "SESSION", session, sessionlen);

	if (conn->session_out) {
		FILE *fp;

		if (!(fp = fopen(conn->session_out, conn->new_session_ticket ? "ab" : "wb"))) {
			error_print();
			return -1;
		}
		if (fwrite(session, 1, sessionlen, fp) != sessionlen) {
			error_print();
			fclose(fp);
			return -1;
		}
		fclose(fp);
	}
	conn->new_session_ticket++;

	return 1;
}

int tls13_new_session_ticket_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	const uint8_t *ticket_nonce;
	size_t ticket_nonce_len;
	const uint8_t *ticket;
	size_t ticket_len;
	const uint8_t *exts;
	size_t extslen;

	// early_data extension
	uint32_t max_early_data_size;


	format_print(fp, fmt, ind, "NewSessionTicket\n");
	ind += 4;

	if (tls_uint32_from_bytes(&ticket_lifetime, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "ticket_lifetime: %"PRIu32" seconds\n", ticket_lifetime);

	if (tls_uint32_from_bytes(&ticket_age_add, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "ticket_age_add: %"PRIu32"\n", ticket_age_add);

	if (tls_uint8array_from_bytes(&ticket_nonce, &ticket_nonce_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "ticket_nonce", ticket_nonce, ticket_nonce_len);

	if (tls_uint16array_from_bytes(&ticket, &ticket_len, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "ticket", ticket, ticket_len);

	format_print(fp, fmt, ind, "extensions\n");
	ind += 4;
	if (tls_uint16array_from_bytes(&exts, &extslen, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	while (extslen) {
		uint16_t ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_uint16_from_bytes(&ext_type, &exts, &extslen) != 1
			|| tls_uint16array_from_bytes(&ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}
		switch (ext_type) {
		case TLS_extension_early_data:
			tls13_early_data_print(fp, fmt, ind + 4, ext_data, ext_datalen);
			break;
		default:
			format_print(fp, fmt, ind, "%s (%d)\n", tls_extension_name(ext_type), ext_type);
			format_bytes(fp, fmt, ind + 4, "raw_data", ext_data, ext_datalen);
			error_print();
		}
	}
	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}



/*
41. pre_shared_key

ClientHello.exts.pre_shared_key
	ext_data := OfferedPsks;

	struct {
		PskIdentity identities<7..2^16-1>;
		PskBinderEntry binders<33..2^16-1>;
	} OfferedPsks;

	struct {
		opaque identity<1..2^16-1>;
		uint32 obfuscated_ticket_age;
	} PskIdentity;

	opaque PskBinderEntry<32..255>;

ServerHello.exts.pre_shared_key
	ext_data := uint16 selected_identity;
*/

int tls13_psk_identity_to_bytes(const uint8_t *ticket, size_t ticketlen, uint32_t obfuscated_ticket_age,
	uint8_t **out, size_t *outlen)
{
	if (!ticket || !ticketlen || ticketlen > 65535) {
		error_print();
		return -1;
	}

	tls_uint16array_to_bytes(ticket, ticketlen, out, outlen);
	tls_uint32_to_bytes(obfuscated_ticket_age, out, outlen);
	return 1;
}

int tls13_psk_identity_from_bytes(const uint8_t **ticket, size_t *ticketlen, uint32_t *obfuscated_ticket_age,
	const uint8_t **in, size_t *inlen)
{
	if (tls_uint16array_from_bytes(ticket, ticketlen, in, inlen) != 1
		|| tls_uint32_from_bytes(obfuscated_ticket_age, in, inlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_psk_binders_generate_empty(const int *psk_cipher_suites, size_t psk_cipher_suites_cnt,
	uint8_t *binders, size_t *binders_len)
{
	const uint8_t empty_binder[64] = {0};
	size_t i;

	if (!psk_cipher_suites || !psk_cipher_suites_cnt || !binders || !binders_len) {
		error_print();
		return -1;
	}

	*binders_len = 0;
	for (i = 0; i < psk_cipher_suites_cnt; i++) {
		const BLOCK_CIPHER *cipher;
		const DIGEST *digest;

		if (tls13_cipher_suite_get(psk_cipher_suites[i], &cipher, &digest) != 1) {
			error_print();
			return -1;
		}
		if (digest->digest_size > sizeof(empty_binder)) {
			error_print();
			return -1;
		}
		tls_uint8array_to_bytes(empty_binder, digest->digest_size, &binders, binders_len);
	}
	return 1;
}

int tls13_psk_binders_generate(
	const int *psk_cipher_suites, size_t psk_cipher_suites_cnt,
	const uint8_t *psk_keys, size_t psk_keys_len,
	const uint8_t *truncated_client_hello, size_t truncated_client_hello_len,
	uint8_t *binders, size_t *binders_len)
{
	const uint8_t zeros[32] = {0};
	DIGEST_CTX null_dgst_ctx;
	DIGEST_CTX dgst_ctx;
	uint8_t secret[32];
	uint8_t *early_secret = secret;
	uint8_t *binder_key = secret;
	uint8_t *binder = secret;
	size_t binderlen;
	size_t i;

	if (!psk_cipher_suites || !psk_cipher_suites_cnt
		|| !psk_keys || !psk_keys_len || !truncated_client_hello
		|| !truncated_client_hello_len || !binders || !binders_len) {
		error_print();
		return -1;
	}

	*binders_len = 0;

	for (i = 0; i < psk_cipher_suites_cnt; i++) {
		const BLOCK_CIPHER *cipher;
		const DIGEST *digest;
		const uint8_t *psk_key;
		size_t psk_key_len;

		if (tls13_cipher_suite_get(psk_cipher_suites[i], &cipher, &digest) != 1) {
			error_print();
			return -1;
		}

		if (digest->digest_size != sizeof(secret)) {
			error_print();
			return -1;
		}
		if (digest_init(&null_dgst_ctx, digest) != 1
			|| digest_init(&dgst_ctx, digest) != 1
			|| digest_update(&dgst_ctx, truncated_client_hello, truncated_client_hello_len) != 1) {
			error_print();
			return -1;
		}

		if (tls_uint8array_from_bytes(&psk_key, &psk_key_len, &psk_keys, &psk_keys_len) != 1) {
			error_print();
			return -1;
		}
		if (psk_key_len != digest->digest_size) {
			gmssl_secure_clear(early_secret, sizeof(early_secret));
			error_print();
			return -1;
		}

		// [1]
		tls13_hkdf_extract(digest, zeros, psk_key, early_secret);
		// [2]
		tls13_derive_secret(early_secret, "res binder", &null_dgst_ctx, binder_key);

		tls13_compute_verify_data(binder_key, &dgst_ctx, binder, &binderlen);

		tls_uint8array_to_bytes(binder, binderlen, &binders, binders_len);
	}

	gmssl_secure_clear(secret, sizeof(secret));
	return 1;
}

int tls13_psk_binder_verify(const DIGEST *digest,
	const uint8_t *pre_shared_key, size_t pre_shared_key_len,
	const DIGEST_CTX *truncated_client_hello_dgst_ctx,
	const uint8_t *binder, size_t binderlen)
{
	uint8_t secret[32] = {0};
	uint8_t *zeros = secret;
	uint8_t *early_secret = secret;
	uint8_t *binder_key = secret;
	uint8_t *local_binder = secret;
	DIGEST_CTX null_dgst_ctx;
	size_t local_binder_len;

	if (digest_init(&null_dgst_ctx, digest) != 1) {
		error_print();
		return -1;
	}

	// [1]
	tls13_hkdf_extract(digest, zeros, pre_shared_key, early_secret);
	// [2]
	tls13_derive_secret(early_secret, "res binder", &null_dgst_ctx, binder_key);

	tls13_compute_verify_data(binder_key, truncated_client_hello_dgst_ctx, local_binder, &local_binder_len);

	if (binderlen != local_binder_len || memcmp(local_binder, binder, binderlen) != 0) {
		return 0;
	}

	return 1;
}

int tls13_client_pre_shared_key_ext_to_bytes(const uint8_t *identities, size_t identitieslen,
	const uint8_t *binders, size_t binderslen, uint8_t **out, size_t *outlen)
{
	int ext_type = TLS_extension_pre_shared_key;
	uint8_t *ext_data = *out + 4;
	size_t ext_datalen = 0;

	tls_uint16array_to_bytes(identities, identitieslen, &ext_data, &ext_datalen);
	tls_uint16array_to_bytes(binders, binderslen, &ext_data, &ext_datalen);
	tls_ext_to_bytes(ext_type, NULL, ext_datalen, out, outlen); // tls_ext_to_bytes 逻辑不一定对啊			

	return 1;
}

int tls13_client_pre_shared_key_from_bytes(const uint8_t **identities, size_t *identitieslen,
	const uint8_t **binders, size_t *binderslen, const uint8_t *ext_data, size_t ext_datalen)
{
	if (tls_uint16array_from_bytes(identities, identitieslen, &ext_data, &ext_datalen) != 1
		|| tls_uint16array_from_bytes(binders, binderslen, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_client_pre_shared_key_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	const uint8_t *identities;
	size_t identitieslen;
	const uint8_t *binders;
	size_t binderslen;

	format_print(fp, fmt, ind, "pre_shared_key\n");
	ind += 4;

	if (tls_uint16array_from_bytes(&identities, &identitieslen, &ext_data, &ext_datalen) != 1
		|| tls_uint16array_from_bytes(&binders, &binderslen, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "identities\n");
	if (!identitieslen) {
		format_print(fp, fmt, ind + 4, "(null)\n");
	}
	while (identitieslen) {
		int indent = ind + 4;
		const uint8_t *ticket;
		size_t ticketlen;
		uint32_t obfuscated_ticket_age;

		if (tls13_psk_identity_from_bytes(&ticket, &ticketlen, &obfuscated_ticket_age, &identities, &identitieslen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, indent, "PskIdentity\n");
		indent += 4;
		format_bytes(fp, fmt, indent, "identity", ticket, ticketlen);
		format_print(fp, fmt, indent, "obfuscated_ticket_age: %"PRIu32"\n", obfuscated_ticket_age);
	}

	format_print(fp, fmt, ind, "binders\n");
	if (!binderslen) {
		format_print(fp, fmt, ind + 4, "(null)\n");
	}
	while (binderslen) {
		int indent = ind + 4;
		const uint8_t *binder;
		size_t binderlen;

		if (tls_uint8array_from_bytes(&binder, &binderlen, &binders, &binderslen) != 1) {
			error_print();
			return -1;
		}
		format_bytes(fp, fmt, indent, "PskBinderEntry", binder, binderlen);
	}


	return 1;
}

int tls13_server_pre_shared_key_ext_to_bytes(int selected_identity, uint8_t **out, size_t *outlen)
{
	int ext_type = TLS_extension_pre_shared_key;
	uint8_t ext_data[2];
	uint8_t *p = ext_data;
	size_t ext_datalen = 0;

	if (selected_identity <= 0 || selected_identity > 65535) {
		error_print();
		return -1;
	}
	tls_uint16_to_bytes((uint16_t)(selected_identity - 1), &p, &ext_datalen);
	tls_ext_to_bytes(ext_type, ext_data, sizeof(ext_data), out, outlen);
	return 1;
}

int tls13_server_pre_shared_key_from_bytes(int *selected_identity, const uint8_t *ext_data, size_t ext_datalen)
{
	uint16_t identity;
	if (tls_uint16_from_bytes(&identity, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	*selected_identity = identity;
	return 1;
}

int tls13_server_pre_shared_key_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	uint16_t identity;
	if (tls_uint16_from_bytes(&identity, &ext_data, &ext_datalen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "seleceted_identity: %d\n", identity);
	if (ext_datalen) {
		error_print();
		return -1;
	}
	return 1;
}

// both client/server
int tls13_add_pre_shared_key(TLS_CONNECT *conn,
	const uint8_t *psk_identity, size_t psk_identity_len,
	const uint8_t *psk_key, size_t psk_key_len,
	int psk_cipher_suite, uint32_t obfuscated_ticket_age)
{
	const BLOCK_CIPHER *cipher;
	const DIGEST *digest;
	uint8_t *psk_identities;
	size_t psk_identities_len;
	uint8_t *psk_keys;
	size_t psk_keys_len;

	if (!conn || !psk_identity || !psk_identity_len || !psk_key || !psk_key_len) {
		error_print();
		return -1;
	}
	if (tls_type_is_in_list(psk_cipher_suite,
		conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt) != 1) {
		error_print();
		return -1;
	}
	if (tls13_cipher_suite_get(psk_cipher_suite, &cipher, &digest) != 1) {
		error_print();
		return -1;
	}
	if (psk_key_len != digest->digest_size) {
		error_print();
		return -1;
	}

	// add psk_identity
	psk_identities_len = conn->psk_identities_len;
	if (tls13_psk_identity_to_bytes(psk_identity, psk_identity_len, obfuscated_ticket_age,
		NULL, &psk_identities_len) != 1) {
		error_print();
		return -1;
	}
	if (psk_identities_len > sizeof(conn->psk_identities)) {
		error_print();
		return -1;
	}
	psk_identities = conn->psk_identities + conn->psk_identities_len;
	tls13_psk_identity_to_bytes(psk_identity, psk_identity_len, obfuscated_ticket_age,
		&psk_identities, &conn->psk_identities_len);


	// add psk_key
	psk_keys_len = conn->psk_keys_len;
	tls_uint8array_to_bytes(psk_key, psk_key_len, NULL, &psk_keys_len);
	if (psk_keys_len > sizeof(conn->psk_keys)) {
		error_print();
		return -1;
	}
	psk_keys = conn->psk_keys + conn->psk_keys_len;
	tls_uint8array_to_bytes(psk_key, psk_key_len, &psk_keys, &conn->psk_keys_len);

	// add psk_cipher_suite
	if (conn->psk_cipher_suites_cnt >= sizeof(conn->psk_cipher_suites)/sizeof(conn->psk_cipher_suites[0])) {
		error_print();
		return -1;
	}
	conn->psk_cipher_suites[conn->psk_cipher_suites_cnt++] = psk_cipher_suite;

	return 1;
}



int tls13_psk_search(
	const uint8_t *psk_identities, size_t psk_identities_len, // server ctx
	const uint8_t *psk_keys, size_t psk_keys_len, // server ctx
	const uint8_t *psk_identity, size_t psk_identity_len, // ClientHello.pre_shared_key
	const uint8_t **psk_key, size_t *psk_key_len, int *psk_key_idx)
{
	size_t i;

	if (!psk_identities || !psk_identities_len || !psk_keys || !psk_keys_len) {
		error_print();
		return -1;
	}
	if (!psk_identity || !psk_identity_len
		|| !psk_key || !psk_key_len) {
		error_print();
		return -1;
	}
	for (i = 0; psk_identities_len; i++) {
		const uint8_t *id;
		size_t idlen;
		uint32_t ticket_age;
		const uint8_t *key;
		size_t keylen;

		if (tls13_psk_identity_from_bytes(&id, &idlen, &ticket_age, &psk_identities, &psk_identities_len) != 1
			|| tls_uint8array_from_bytes(&key, &keylen, &psk_keys, &psk_keys_len) != 1) {
			error_print();
			return -1;
		}
		if (idlen == psk_identity_len
			&& memcmp(id, psk_identity, psk_identity_len) == 0) {
			*psk_key = key;
			*psk_key_len = keylen;
			*psk_key_idx = i;
			return 1;
		}
	}
	return 0;
}

int tls13_process_client_pre_shared_key_external(TLS_CONNECT *conn,
	const uint8_t *ext_data, size_t ext_datalen)
{
	int ret;
	const uint8_t *identities;
	size_t identitieslen;
	const uint8_t *binders;
	size_t binderslen;
	const uint8_t *truncated_binders;
	size_t truncated_binderslen;
	size_t i;

	if (!conn || !ext_data || !ext_datalen) {
		error_print();
		return -1;
	}
	if (!conn->psk_cipher_suites_cnt || !conn->psk_identities_len || !conn->psk_keys_len) {
		error_print();
		return -1;
	}

	// parse pre_shared_key extension
	if (tls_uint16array_from_bytes(&identities, &identitieslen, &ext_data, &ext_datalen) != 1
		|| tls_uint16array_from_bytes(&binders, &binderslen, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}

	// truncate client_hello => plain_record
	memcpy(conn->plain_record, conn->record, conn->recordlen);
	conn->plain_recordlen = conn->recordlen;
	truncated_binders = conn->plain_record + (binders - conn->record);
	truncated_binderslen = binderslen;
	while (truncated_binderslen) {
		const uint8_t *truncated_binder;
		size_t truncated_binderlen;
		if (tls_uint8array_from_bytes(&truncated_binder, &truncated_binderlen,
			&truncated_binders, &truncated_binderslen) != 1) {
			error_print();
			return -1;
		}
		memset((uint8_t *)truncated_binder, 0, truncated_binderlen);
	}

	// search psk
	for (i = 0; identitieslen; i++) {
		const uint8_t *identity;
		size_t identitylen;
		uint32_t obfuscated_ticket_age;
		const uint8_t *binder;
		size_t binderlen;
		const uint8_t *matched_psk;
		size_t matched_psk_len;
		int matched_psk_idx;

		int cipher_suite;

		DIGEST_CTX dgst_ctx;

		// get psk_identity, psk_key, age and binder, age is useless whne psk is external
		if (tls13_psk_identity_from_bytes(&identity, &identitylen, &obfuscated_ticket_age,
			&identities, &identitieslen) != 1
			|| tls_uint8array_from_bytes(&binder, &binderlen,
			&binders, &binderslen) != 1) {
			error_print();
			return -1;
		}

		// search psk by psk_identity
		if ((ret = tls13_psk_search(
			conn->psk_identities, conn->psk_identities_len,
			conn->psk_keys, conn->psk_keys_len,
			identity, identitylen,
			&matched_psk, &matched_psk_len, &matched_psk_idx)) < 0) {
			error_print();
			return -1;
		} else if (ret == 0) {
			continue;
		}

		conn->cipher_suite = conn->psk_cipher_suites[matched_psk_idx];

		if (tls13_cipher_suite_get(conn->cipher_suite, &conn->cipher, &conn->digest) != 1) {
			error_print();
			return -1;
		}

		// verify binder
		if (digest_init(&dgst_ctx, conn->digest) != 1
			|| digest_update(&dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if ((ret = tls13_psk_binder_verify(conn->digest, matched_psk, matched_psk_len,
			&dgst_ctx, binder, binderlen)) < 0) {
			error_print();
			return -1;
		} else if (ret == 0) {
			continue;
		}

		// set psk
		memcpy(conn->psk, matched_psk, matched_psk_len);
		conn->psk_len = matched_psk_len;
		conn->selected_psk_identity = (int)i + 1;
		break;
	}

	if (!conn->selected_psk_identity) {
		return 0;
	}
	return 1;
}

int tls13_process_client_pre_shared_key_from_ticket(TLS_CONNECT *conn,
	const uint8_t *ext_data, size_t ext_datalen)
{
	int ret;
	const uint8_t *identities;
	size_t identitieslen;
	const uint8_t *binders;
	size_t binderslen;
	const uint8_t *truncated_binders;
	size_t truncated_binderslen;
	size_t i;

	if (!conn || !ext_data || !ext_datalen) {
		error_print();
		return -1;
	}
	if (!conn->ctx->session_ticket_key) {
		error_print();
		return -1;
	}
	if (!conn->digest) {
		error_print();
		return -1;
	}
	if (conn->selected_psk_identity) {
		error_print();
		return -1;
	}

	// parse pre_shared_key extension
	if (tls_uint16array_from_bytes(&identities, &identitieslen, &ext_data, &ext_datalen) != 1
		|| tls_uint16array_from_bytes(&binders, &binderslen, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}

	// truncate client_hello
	memcpy(conn->plain_record, conn->record, conn->recordlen);
	conn->plain_recordlen = conn->recordlen;
	truncated_binders = conn->plain_record + (binders - conn->record);
	truncated_binderslen = binderslen;
	while (truncated_binderslen) {
		const uint8_t *truncated_binder;
		size_t truncated_binderlen;
		if (tls_uint8array_from_bytes(&truncated_binder, &truncated_binderlen,
			&truncated_binders, &truncated_binderslen) != 1) {
			error_print();
			return -1;
		}
		memset((uint8_t *)truncated_binder, 0, truncated_binderlen);
	}

	// search psk
	for (i = 0; identitieslen; i++) {
		const uint8_t *ticket;
		size_t ticketlen;
		uint32_t obfuscated_ticket_age;
		const uint8_t *binder;
		size_t binderlen;

		// ticket content
		uint8_t pre_shared_key[32];
		int protocol_version;
		int cipher_suite;
		uint32_t ticket_issue_time;
		uint32_t ticket_lifetime;
		DIGEST_CTX dgst_ctx;

		// get psk_identity, psk_key, age and binder
		if (tls13_psk_identity_from_bytes(&ticket, &ticketlen, &obfuscated_ticket_age,
			&identities, &identitieslen) != 1
			|| tls_uint8array_from_bytes(&binder, &binderlen,
			&binders, &binderslen) != 1) {
			error_print();
			return -1;
		}

		// decrypt ticket
		if (tls13_ticket_decrypt(conn->ctx->session_ticket_key, ticket, ticketlen,
			pre_shared_key, &protocol_version, &cipher_suite,
			&ticket_issue_time, &ticket_lifetime) != 1) {
			continue;
		}

		// check protocol_version and cipher_suite
		if (protocol_version != conn->protocol
			|| cipher_suite != conn->cipher_suite) {
			continue;
		}

		// check time
		uint32_t current_time = time(NULL);
		if (ticket_issue_time > current_time) {
			error_print();
			continue;
		}
		if (current_time - ticket_issue_time > ticket_lifetime) {
			error_print();
			continue;
		}

		// verify binder
		if (digest_init(&dgst_ctx, conn->digest) != 1
			|| digest_update(&dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if ((ret = tls13_psk_binder_verify(conn->digest,
			pre_shared_key, sizeof(pre_shared_key),
			&dgst_ctx, binder, binderlen)) != 1) {
			error_print();
			return -1;
		} else if (ret == 0) {
			continue;
		}

		// set psk
		memcpy(conn->psk, pre_shared_key, sizeof(pre_shared_key));
		conn->psk_len = sizeof(pre_shared_key);
		conn->selected_psk_identity = (int)i + 1;
		break;
	}

	if (!conn->selected_psk_identity) {
		return 0;
	}
	return 1;
}

int tls13_enable_pre_shared_key(TLS_CONNECT *conn, int enable)
{
	if (!conn) {
		error_print();
		return -1;
	}
	conn->pre_shared_key = enable ? 1 : 0;
	return 1;
}





































/*

early_data

	ClientHello.early_data
		ext_data := empty

	EncryptedExtensions.early_data
		ext_data := empty

	NewSessionTicket.early_data
		ext_data := uint32 max_early_data_size;

*/

int tls13_early_data_ext_to_bytes(size_t max_early_data_size, uint8_t **out, size_t *outlen)
{
	uint8_t ext_data[4];
	uint8_t *p = ext_data;
	size_t ext_datalen = 0;
	tls_uint32_to_bytes(max_early_data_size, &p, &ext_datalen);
	if (tls_ext_to_bytes(TLS_extension_early_data, ext_data, ext_datalen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_early_data_from_bytes(size_t *max_early_data_size, const uint8_t *ext_data, size_t ext_datalen)
{
	uint32_t max_size;
	if (tls_uint32_from_bytes(&max_size, &ext_data, &ext_datalen) != 1
		|| tls_length_is_zero(ext_datalen) != 1) {
		error_print();
		return -1;
	}
	*max_early_data_size = max_size;
	return 1;
}

int tls13_early_data_print(FILE *fp, int fmt, int ind, const uint8_t *ext_data, size_t ext_datalen)
{
	uint32_t max_early_data_size;

	if (!ext_data || !ext_datalen) {
		format_print(fp, fmt, ind, "(null)\n");
	} else {
		if (tls_uint32_from_bytes(&max_early_data_size, &ext_data, &ext_datalen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "max_early_data_size: %"PRIu32"\n", max_early_data_size);
		if (ext_datalen) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int tls13_set_early_data(TLS_CONNECT *conn, const uint8_t *data, size_t datalen)
{
	size_t len;

	if (!conn) {
		error_print();
		return -1;
	}
	if (!conn->is_client) {
		error_print();
		return -1;
	}
	if (!data || !datalen || datalen > sizeof(conn->early_data_buf)) {
		error_print();
		return -1;
	}
	if (!(conn->key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK))) {
		error_print();
		return -1;
	}
	memcpy(conn->early_data_buf, data, datalen);
	conn->early_data_len = datalen;
	conn->early_data = 1;
	return 1;
}

// 同时影响客户端和服务器吗？
int tls13_enable_early_data(TLS_CONNECT *conn, int enable)
{
	if (!conn) {
		error_print();
		return -1;
	}
	conn->early_data = enable ? 1 : 0;
	return 1;
}


int tls13_ctx_set_max_early_data_size(TLS_CTX *ctx, size_t max_early_data_size)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	// 是否有必要在CTX中做过多的状态触发？
	ctx->max_early_data_size = max_early_data_size;
	return 1;
}

int tls13_set_max_early_data_size(TLS_CONNECT *conn, size_t max_early_data_size)
{
	if (!conn) {
		error_print();
		return -1;
	}
	if (max_early_data_size > sizeof(conn->early_data)) {
		error_print();
		return -1;
	}
	conn->max_early_data_size = max_early_data_size;
	conn->early_data = max_early_data_size ? 1 : 0;
	return 1;
}


// 不应该弄一个独立的函数
int tls13_psk_keys_get_first(const uint8_t *keys, size_t keyslen, const uint8_t **key, size_t *keylen)
{
	if (tls_uint8array_from_bytes(key, keylen, &keys, &keyslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
// 这个函数和密码计算有关，应该放到外面
int tls13_generate_early_data_keys(TLS_CONNECT *conn)
{
	uint8_t zeros[32] = {0};
	const uint8_t *first_psk;
	size_t first_psk_len;
	uint8_t early_secret[32];
	uint8_t client_early_traffic_secret[32];
	uint8_t client_write_key[16];

	if (tls13_cipher_suite_get(conn->psk_cipher_suites[0], &conn->cipher, &conn->digest) != 1) {
		error_print();
		return -1;
	}

	if (digest_init(&conn->dgst_ctx, conn->digest) != 1
		|| digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	// early_data always encrypted with the first psk
	if (tls13_psk_keys_get_first(conn->psk_keys, conn->psk_keys_len, &first_psk, &first_psk_len) != 1) {
		error_print();
		return -1;
	}

	// psk => client_early_traffic_secret
	tls13_hkdf_extract(conn->digest, zeros, first_psk, early_secret);
	tls13_derive_secret(early_secret, "c e traffic", &conn->dgst_ctx, client_early_traffic_secret);
	tls13_hkdf_expand_label(conn->digest, client_early_traffic_secret, "key", NULL, 0, 16, client_write_key);
	block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
	tls13_hkdf_expand_label(conn->digest, client_early_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	tls_seq_num_reset(conn->client_seq_num);

	format_print(stderr, 0, 0, "client_write_key/iv <= client_early_traffic_secret\n");
	format_bytes(stderr, 0, 4, "client_early_traffic_secret", client_early_traffic_secret, 32);
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);

	return 1;
}





// EndOfEarlyData

int tls13_record_set_handshake_end_of_early_data(uint8_t *record, size_t *recordlen)
{
	int type = TLS_handshake_end_of_early_data;
	tls_record_set_handshake(record, recordlen, type, NULL, 0);
	return 1;
}

int tls13_record_get_handshake_end_of_early_data(uint8_t *record)
{
	int type;
	const uint8_t *cp;
	size_t len;

	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_end_of_early_data) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_end_of_early_data_print(FILE *fp, int fmt, int ind, const uint8_t *d, size_t dlen)
{
	format_print(fp, fmt, ind, "EndOfEarlyData\n");
	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}

int tls13_send_end_of_early_data(TLS_CONNECT *conn)
{
	int ret;

	if (!conn->recordlen) {
		if (tls13_record_set_handshake_end_of_early_data(conn->plain_record, &conn->plain_recordlen) != 1) {
			error_print();
			return -1;
		}
		tls_trace("send EndOfEarlyData\n");

		format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);

		size_t padding_len;
		tls13_padding_len_rand(&padding_len);
		if (tls13_record_encrypt(&conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, conn->plain_record, conn->plain_recordlen, padding_len,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	// 这里是生成handshake密钥，是一个独立逻辑，不应该直接放在这里

	uint8_t client_write_key[16];
	tls13_hkdf_expand_label(conn->digest, conn->client_handshake_traffic_secret, "key", NULL, 0, 16, client_write_key);
	block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
	tls13_hkdf_expand_label(conn->digest, conn->client_handshake_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	tls_seq_num_reset(conn->client_seq_num);

	// client_early_traffic_secret 用来加密early_data, end_of_early_data
	format_print(stderr, 0, 0, "client_write_key/iv <= client_handshake_traffic_secret\n");
	format_bytes(stderr, 0, 4, "client_handshake_traffic_secret", conn->client_handshake_traffic_secret, 32);
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);

	tls_clean_record(conn);
	return 1;

}

int tls13_recv_end_of_early_data(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("recv {EndOfEarlyData}\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}


	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);

	if (tls13_record_decrypt(&conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls13_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls13_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	if ((ret = tls13_record_get_handshake_end_of_early_data(conn->plain_record)) < 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls13_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}


	// 这里是生成handshake密钥，是一个独立逻辑，不应该直接放在这里

	uint8_t client_write_key[16];
	tls13_hkdf_expand_label(conn->digest, conn->client_handshake_traffic_secret, "key", NULL, 0, 16, client_write_key);
	block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, client_write_key);
	tls13_hkdf_expand_label(conn->digest, conn->client_handshake_traffic_secret, "iv", NULL, 0, 12, conn->client_write_iv);
	tls_seq_num_reset(conn->client_seq_num);

	format_print(stderr, 0, 0, "client_write_key/iv <= client_handshake_traffic_secret\n");
	format_bytes(stderr, 0, 4, "client_handshake_traffic_secret", conn->client_handshake_traffic_secret, 32);
	format_bytes(stderr, 0, 4, "client_write_key", client_write_key, 16);
	format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 12);

	return 1;
}

