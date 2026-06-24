/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <inttypes.h>
#include <string.h>
#include <gmssl/aes.h>
#include <gmssl/sm4.h>
#include <gmssl/oid.h>
#include <gmssl/quic.h>
#include <gmssl/tls.h>
#include <gmssl/hkdf.h>
#include <gmssl/digest.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>


static const uint8_t quic_v1_initial_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
};

int tls13_generate_early_keys(TLS_CONNECT *conn);
int tls13_generate_handshake_secrets(TLS_CONNECT *conn);
int tls13_generate_master_secret(TLS_CONNECT *conn);
int tls13_generate_client_handshake_keys(TLS_CONNECT *conn);
int tls13_generate_server_handshake_keys(TLS_CONNECT *conn);
int tls13_handshake_print(FILE *fp, int fmt, int ind, const uint8_t *handshake, size_t handshake_len);


static int quic_tls_handshake_to_bytes(TLS_CONNECT *conn, int level, uint8_t **out, size_t *outlen)
{
	const uint8_t *handshake;
	size_t handshake_len;

	if (!conn || !outlen) {
		error_print();
		return -1;
	}
	if (conn->recordlen < TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE
		|| tls_record_type(conn->record) != TLS_record_handshake
		|| tls_record_length(conn->record) != conn->recordlen) {
		error_print();
		return -1;
	}

	handshake = conn->record + TLS_RECORD_HEADER_SIZE;
	handshake_len = conn->recordlen - TLS_RECORD_HEADER_SIZE;
	if (out && *out) {
		memcpy(*out, handshake, handshake_len);
		*out += handshake_len;
	}
	*outlen += handshake_len;
	memcpy(conn->plain_record, handshake, handshake_len);
	conn->plain_recordlen = handshake_len;
	if (conn->verbose) {
		quic_crypto_data_print(stderr, 0, 0, level, handshake, handshake_len);
	}
	return 1;
}


size_t quic_varint_size(uint64_t val)
{
	if (val <= 63) {
		return 1;
	} else if (val <= 16383) {
		return 2;
	} else if (val <= 1073741823) {
		return 4;
	} else if (val <= 4611686018427387903ULL) {
		return 8;
	}
	return 0;
}

int quic_varint_to_bytes(uint64_t val, uint8_t **out, size_t *outlen)
{
	size_t len;

	if (!outlen) {
		error_print();
		return -1;
	}

	len = quic_varint_size(val);
	if (!len) {
		error_print();
		return -1;
	}

	if (out && *out) {
		switch (len) {
		case 1:
			*(*out)++ = (uint8_t)val;
			break;
		case 2:
			*(*out)++ = (uint8_t)(0x40 | (val >> 8));
			*(*out)++ = (uint8_t)val;
			break;
		case 4:
			*(*out)++ = (uint8_t)(0x80 | (val >> 24));
			*(*out)++ = (uint8_t)(val >> 16);
			*(*out)++ = (uint8_t)(val >> 8);
			*(*out)++ = (uint8_t)val;
			break;
		case 8:
			*(*out)++ = (uint8_t)(0xc0 | (val >> 56));
			*(*out)++ = (uint8_t)(val >> 48);
			*(*out)++ = (uint8_t)(val >> 40);
			*(*out)++ = (uint8_t)(val >> 32);
			*(*out)++ = (uint8_t)(val >> 24);
			*(*out)++ = (uint8_t)(val >> 16);
			*(*out)++ = (uint8_t)(val >> 8);
			*(*out)++ = (uint8_t)val;
			break;
		default:
			error_print();
			return -1;
		}
	}

	*outlen += len;
	return 1;
}

int quic_varint_from_bytes(uint64_t *val, const uint8_t **in, size_t *inlen)
{
	uint8_t first;
	size_t len;
	uint64_t ret;
	size_t i;

	if (!val || !in || !*in || !inlen || !*inlen) {
		error_print();
		return -1;
	}

	first = **in;
	len = (size_t)1 << (first >> 6);
	if (*inlen < len) {
		error_print();
		return -1;
	}

	ret = first & 0x3f;
	for (i = 1; i < len; i++) {
		ret <<= 8;
		ret |= (*in)[i];
	}

	*val = ret;
	*in += len;
	*inlen -= len;
	return 1;
}

const char *quic_packet_type_name(int type)
{
	switch (type) {
	case QUIC_packet_initial:
		return "Initial";
	case QUIC_packet_0_rtt:
		return "0-RTT";
	case QUIC_packet_handshake:
		return "Handshake";
	case QUIC_packet_retry:
		return "Retry";
	default:
		return "Unknown";
	}
}

const char *quic_frame_type_name(uint64_t type)
{
	switch (type) {
	case QUIC_frame_padding:
		return "PADDING";
	case QUIC_frame_ping:
		return "PING";
	case QUIC_frame_ack:
		return "ACK";
	case QUIC_frame_ack_ecn:
		return "ACK_ECN";
	case QUIC_frame_reset_stream:
		return "RESET_STREAM";
	case QUIC_frame_stop_sending:
		return "STOP_SENDING";
	case QUIC_frame_crypto:
		return "CRYPTO";
	case QUIC_frame_new_token:
		return "NEW_TOKEN";
	case QUIC_frame_max_data:
		return "MAX_DATA";
	case QUIC_frame_max_stream_data:
		return "MAX_STREAM_DATA";
	case QUIC_frame_max_streams_bidi:
		return "MAX_STREAMS_BIDI";
	case QUIC_frame_max_streams_uni:
		return "MAX_STREAMS_UNI";
	case QUIC_frame_data_blocked:
		return "DATA_BLOCKED";
	case QUIC_frame_stream_data_blocked:
		return "STREAM_DATA_BLOCKED";
	case QUIC_frame_streams_blocked_bidi:
		return "STREAMS_BLOCKED_BIDI";
	case QUIC_frame_streams_blocked_uni:
		return "STREAMS_BLOCKED_UNI";
	case QUIC_frame_new_connection_id:
		return "NEW_CONNECTION_ID";
	case QUIC_frame_retire_connection_id:
		return "RETIRE_CONNECTION_ID";
	case QUIC_frame_path_challenge:
		return "PATH_CHALLENGE";
	case QUIC_frame_path_response:
		return "PATH_RESPONSE";
	case QUIC_frame_connection_close:
		return "CONNECTION_CLOSE";
	case QUIC_frame_connection_close_app:
		return "CONNECTION_CLOSE_APP";
	case QUIC_frame_handshake_done:
		return "HANDSHAKE_DONE";
	default:
		if (type >= 0x08 && type <= 0x0f) {
			return "STREAM";
		}
		return "UNKNOWN";
	}
}

const char *quic_encryption_level_name(int level)
{
	switch (level) {
	case QUIC_encryption_initial:
		return "initial";
	case QUIC_encryption_early_data:
		return "early_data";
	case QUIC_encryption_handshake:
		return "handshake";
	case QUIC_encryption_application:
		return "application";
	default:
		return "unknown";
	}
}

static int quic_bytes_get(const uint8_t **in, size_t *inlen, const uint8_t **data, size_t datalen)
{
	if (!in || !*in || !inlen || !data || *inlen < datalen) {
		error_print();
		return -1;
	}
	*data = *in;
	*in += datalen;
	*inlen -= datalen;
	return 1;
}

int quic_crypto_data_print(FILE *fp, int fmt, int ind, int level, const uint8_t *data, size_t datalen)
{
	const uint8_t *p = data;
	size_t len = datalen;

	if (!fp || (!data && datalen)) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "CRYPTO Data\n");
	ind += 4;
	format_print(fp, fmt, ind, "Level: %s\n", quic_encryption_level_name(level));
	format_print(fp, fmt, ind, "Length: %zu\n", datalen);

	while (len) {
		size_t handshake_len;

		if (len < TLS_HANDSHAKE_HEADER_SIZE) {
			format_bytes(fp, fmt, ind, "fragment", p, len);
			return 1;
		}
		handshake_len = TLS_HANDSHAKE_HEADER_SIZE + (((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3]);
		if (handshake_len > len) {
			format_bytes(fp, fmt, ind, "fragment", p, len);
			return 1;
		}
		if (tls13_handshake_print(fp, fmt, ind, p, handshake_len) != 1) {
			format_bytes(fp, fmt, ind, "handshake", p, handshake_len);
		}
		p += handshake_len;
		len -= handshake_len;
	}

	return 1;
}

int quic_frame_print(FILE *fp, int fmt, int ind, int level, const uint8_t **in, size_t *inlen)
{
	const uint8_t *p;
	size_t len;
	uint64_t type;
	uint64_t val;

	if (!fp || !in || !*in || !inlen || !*inlen) {
		error_print();
		return -1;
	}

	p = *in;
	len = *inlen;
	if (quic_varint_from_bytes(&type, &p, &len) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "Frame\n");
	ind += 4;
	format_print(fp, fmt, ind, "Type: %s (0x%" PRIx64 ")\n", quic_frame_type_name(type), type);

	switch (type) {
	case QUIC_frame_padding:
		while (len && *p == 0) {
			p++;
			len--;
		}
		format_print(fp, fmt, ind, "Length: %zu\n", (size_t)(p - *in));
		break;
	case QUIC_frame_ping:
	case QUIC_frame_handshake_done:
		break;
	case QUIC_frame_ack:
	case QUIC_frame_ack_ecn:
		if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
		format_print(fp, fmt, ind, "Largest Acknowledged: %" PRIu64 "\n", val);
		if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
		format_print(fp, fmt, ind, "ACK Delay: %" PRIu64 "\n", val);
		if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
		format_print(fp, fmt, ind, "ACK Range Count: %" PRIu64 "\n", val);
		{
			uint64_t range_count = val;
			uint64_t i;
			if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
			format_print(fp, fmt, ind, "First ACK Range: %" PRIu64 "\n", val);
			for (i = 0; i < range_count; i++) {
				uint64_t gap;
				uint64_t ack_range;
				if (quic_varint_from_bytes(&gap, &p, &len) != 1 || quic_varint_from_bytes(&ack_range, &p, &len) != 1) return -1;
				format_print(fp, fmt, ind, "ACK Range[%" PRIu64 "]: gap=%" PRIu64 ", range=%" PRIu64 "\n", i, gap, ack_range);
			}
		}
		if (type == QUIC_frame_ack_ecn) {
			if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
			format_print(fp, fmt, ind, "ECT0 Count: %" PRIu64 "\n", val);
			if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
			format_print(fp, fmt, ind, "ECT1 Count: %" PRIu64 "\n", val);
			if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
			format_print(fp, fmt, ind, "CE Count: %" PRIu64 "\n", val);
		}
		break;
	case QUIC_frame_reset_stream:
		if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
		format_print(fp, fmt, ind, "Stream ID: %" PRIu64 "\n", val);
		if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
		format_print(fp, fmt, ind, "Application Error Code: %" PRIu64 "\n", val);
		if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
		format_print(fp, fmt, ind, "Final Size: %" PRIu64 "\n", val);
		break;
	case QUIC_frame_stop_sending:
		if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
		format_print(fp, fmt, ind, "Stream ID: %" PRIu64 "\n", val);
		if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
		format_print(fp, fmt, ind, "Application Error Code: %" PRIu64 "\n", val);
		break;
	case QUIC_frame_crypto:
		{
			uint64_t offset;
			uint64_t data_len;
			const uint8_t *data;
			if (quic_varint_from_bytes(&offset, &p, &len) != 1 || quic_varint_from_bytes(&data_len, &p, &len) != 1) return -1;
			if (data_len > len || quic_bytes_get(&p, &len, &data, (size_t)data_len) != 1) return -1;
			format_print(fp, fmt, ind, "Offset: %" PRIu64 "\n", offset);
			format_print(fp, fmt, ind, "Length: %" PRIu64 "\n", data_len);
			quic_crypto_data_print(fp, fmt, ind, level, data, (size_t)data_len);
		}
		break;
	case QUIC_frame_new_token:
		{
			const uint8_t *token;
			if (quic_varint_from_bytes(&val, &p, &len) != 1 || val > len || quic_bytes_get(&p, &len, &token, (size_t)val) != 1) return -1;
			format_bytes(fp, fmt, ind, "Token", token, (size_t)val);
		}
		break;
	case QUIC_frame_max_data:
	case QUIC_frame_max_streams_bidi:
	case QUIC_frame_max_streams_uni:
	case QUIC_frame_data_blocked:
	case QUIC_frame_streams_blocked_bidi:
	case QUIC_frame_streams_blocked_uni:
	case QUIC_frame_retire_connection_id:
		if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
		format_print(fp, fmt, ind, "Value: %" PRIu64 "\n", val);
		break;
	case QUIC_frame_max_stream_data:
	case QUIC_frame_stream_data_blocked:
		if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
		format_print(fp, fmt, ind, "Stream ID: %" PRIu64 "\n", val);
		if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
		format_print(fp, fmt, ind, "Value: %" PRIu64 "\n", val);
		break;
	case QUIC_frame_new_connection_id:
		{
			uint64_t seq;
			uint64_t retire_prior_to;
			const uint8_t *cid;
			const uint8_t *token;
			if (quic_varint_from_bytes(&seq, &p, &len) != 1 || quic_varint_from_bytes(&retire_prior_to, &p, &len) != 1) return -1;
			if (!len) return -1;
			val = *p++;
			len--;
			if (val > len || val > 20 || quic_bytes_get(&p, &len, &cid, (size_t)val) != 1 || quic_bytes_get(&p, &len, &token, 16) != 1) return -1;
			format_print(fp, fmt, ind, "Sequence Number: %" PRIu64 "\n", seq);
			format_print(fp, fmt, ind, "Retire Prior To: %" PRIu64 "\n", retire_prior_to);
			format_bytes(fp, fmt, ind, "Connection ID", cid, (size_t)val);
			format_bytes(fp, fmt, ind, "Stateless Reset Token", token, 16);
		}
		break;
	case QUIC_frame_path_challenge:
	case QUIC_frame_path_response:
		{
			const uint8_t *data;
			if (quic_bytes_get(&p, &len, &data, 8) != 1) return -1;
			format_bytes(fp, fmt, ind, "Data", data, 8);
		}
		break;
	case QUIC_frame_connection_close:
	case QUIC_frame_connection_close_app:
		{
			uint64_t reason_len;
			const uint8_t *reason;
			if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
			format_print(fp, fmt, ind, "Error Code: %" PRIu64 "\n", val);
			if (type == QUIC_frame_connection_close) {
				if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
				format_print(fp, fmt, ind, "Frame Type: %s (0x%" PRIx64 ")\n", quic_frame_type_name(val), val);
			}
			if (quic_varint_from_bytes(&reason_len, &p, &len) != 1 || reason_len > len || quic_bytes_get(&p, &len, &reason, (size_t)reason_len) != 1) return -1;
			format_bytes(fp, fmt, ind, "Reason Phrase", reason, (size_t)reason_len);
		}
		break;
	default:
		if (type >= 0x08 && type <= 0x0f) {
			uint64_t stream_id;
			uint64_t offset = 0;
			uint64_t data_len;
			const uint8_t *data;
			if (quic_varint_from_bytes(&stream_id, &p, &len) != 1) return -1;
			if (type & 0x04) {
				if (quic_varint_from_bytes(&offset, &p, &len) != 1) return -1;
			}
			if (type & 0x02) {
				if (quic_varint_from_bytes(&data_len, &p, &len) != 1) return -1;
			} else {
				data_len = len;
			}
			if (data_len > len || quic_bytes_get(&p, &len, &data, (size_t)data_len) != 1) return -1;
			format_print(fp, fmt, ind, "Stream ID: %" PRIu64 "\n", stream_id);
			format_print(fp, fmt, ind, "FIN: %d\n", (type & 0x01) ? 1 : 0);
			format_print(fp, fmt, ind, "Offset: %" PRIu64 "\n", offset);
			format_print(fp, fmt, ind, "Length: %" PRIu64 "\n", data_len);
			format_bytes(fp, fmt, ind, "Data", data, (size_t)data_len);
			break;
		}
		format_bytes(fp, fmt, ind, "Raw", p, len);
		p += len;
		len = 0;
		break;
	}

	*in = p;
	*inlen = len;
	return 1;
}

int quic_frames_print(FILE *fp, int fmt, int ind, int level, const uint8_t *frames, size_t frameslen)
{
	const uint8_t *p = frames;
	size_t len = frameslen;

	if (!fp || (!frames && frameslen)) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "Frames\n");
	ind += 4;
	format_print(fp, fmt, ind, "Level: %s\n", quic_encryption_level_name(level));
	format_print(fp, fmt, ind, "Length: %zu\n", frameslen);

	while (len) {
		if (quic_frame_print(fp, fmt, ind, level, &p, &len) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}

int quic_packet_print(FILE *fp, int fmt, int ind, const uint8_t *packet, size_t packetlen)
{
	const uint8_t *p = packet;
	size_t len = packetlen;
	uint8_t first;

	if (!fp || !packet || !packetlen) {
		error_print();
		return -1;
	}

	first = *p++;
	len--;
	format_print(fp, fmt, ind, "QUIC Packet\n");
	ind += 4;
	format_print(fp, fmt, ind, "Header Form: %s\n", (first & 0x80) ? "long" : "short");
	format_print(fp, fmt, ind, "Fixed Bit: %d\n", (first & 0x40) ? 1 : 0);

	if (first & 0x80) {
		uint32_t version;
		uint8_t type = (first >> 4) & 0x03;
		uint8_t pn_len = (first & 0x03) + 1;
		uint8_t cid_len;
		const uint8_t *cid;
		uint64_t val;

		if (len < 4) return -1;
		version = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
		p += 4;
		len -= 4;
		format_print(fp, fmt, ind, "Type: %s (%u)\n", quic_packet_type_name(type), type);
		format_print(fp, fmt, ind, "Version: 0x%08x\n", version);
		format_print(fp, fmt, ind, "Packet Number Length: %u\n", pn_len);

		if (!len) return -1;
		cid_len = *p++;
		len--;
		if (cid_len > len || quic_bytes_get(&p, &len, &cid, cid_len) != 1) return -1;
		format_bytes(fp, fmt, ind, "Destination Connection ID", cid, cid_len);
		if (!len) return -1;
		cid_len = *p++;
		len--;
		if (cid_len > len || quic_bytes_get(&p, &len, &cid, cid_len) != 1) return -1;
		format_bytes(fp, fmt, ind, "Source Connection ID", cid, cid_len);

		if (type == QUIC_packet_retry) {
			if (len >= 16) {
				format_bytes(fp, fmt, ind, "Retry Token", p, len - 16);
				format_bytes(fp, fmt, ind, "Retry Integrity Tag", p + len - 16, 16);
			} else {
				format_bytes(fp, fmt, ind, "Retry Token", p, len);
			}
			return 1;
		}

		if (type == QUIC_packet_initial) {
			const uint8_t *token;
			if (quic_varint_from_bytes(&val, &p, &len) != 1 || val > len || quic_bytes_get(&p, &len, &token, (size_t)val) != 1) return -1;
			format_bytes(fp, fmt, ind, "Token", token, (size_t)val);
		}
		if (quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
		format_print(fp, fmt, ind, "Length: %" PRIu64 "\n", val);
		format_bytes(fp, fmt, ind, "Protected Payload", p, len);
	} else {
		format_print(fp, fmt, ind, "Key Phase: %d\n", (first & 0x04) ? 1 : 0);
		format_print(fp, fmt, ind, "Packet Number Length: %u\n", (first & 0x03) + 1);
		format_bytes(fp, fmt, ind, "Short Header Packet", packet, packetlen);
	}

	return 1;
}

void quic_transport_params_init(QUIC_TRANSPORT_PARAMS *params)
{
	if (params) {
		memset(params, 0, sizeof(*params));
	}
}

int quic_transport_params_add(QUIC_TRANSPORT_PARAMS *params,
	uint64_t id, const uint8_t *data, size_t datalen)
{
	QUIC_TRANSPORT_PARAM *param;
	size_t i;

	if (!params || (!data && datalen)) {
		error_print();
		return -1;
	}
	if (!quic_varint_size(id) || datalen > QUIC_TRANSPORT_PARAM_MAX_SIZE) {
		error_print();
		return -1;
	}
	if (params->params_count >= QUIC_TRANSPORT_PARAM_MAX_COUNT) {
		error_print();
		return -1;
	}
	for (i = 0; i < params->params_count; i++) {
		if (params->params[i].id == id) {
			error_print();
			return -1;
		}
	}

	param = &params->params[params->params_count++];
	param->id = id;
	param->datalen = datalen;
	if (datalen) {
		memcpy(param->data, data, datalen);
	}
	return 1;
}

int quic_transport_params_add_varint(QUIC_TRANSPORT_PARAMS *params,
	uint64_t id, uint64_t val)
{
	uint8_t buf[8];
	uint8_t *p = buf;
	size_t len = 0;

	if (quic_varint_to_bytes(val, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (quic_transport_params_add(params, id, buf, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int quic_transport_params_get(const QUIC_TRANSPORT_PARAMS *params,
	uint64_t id, const uint8_t **data, size_t *datalen)
{
	size_t i;

	if (!params || !data || !datalen) {
		error_print();
		return -1;
	}

	for (i = 0; i < params->params_count; i++) {
		if (params->params[i].id == id) {
			*data = params->params[i].datalen ? params->params[i].data : NULL;
			*datalen = params->params[i].datalen;
			return 1;
		}
	}

	return 0;
}

int quic_transport_params_get_varint(const QUIC_TRANSPORT_PARAMS *params,
	uint64_t id, uint64_t *val)
{
	const uint8_t *data;
	size_t datalen;
	int ret;

	if (!val) {
		error_print();
		return -1;
	}
	if ((ret = quic_transport_params_get(params, id, &data, &datalen)) != 1) {
		return ret;
	}
	if (quic_varint_from_bytes(val, &data, &datalen) != 1 || datalen != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int quic_transport_params_to_bytes(const QUIC_TRANSPORT_PARAMS *params,
	uint8_t **out, size_t *outlen)
{
	size_t i;

	if (!params || !outlen) {
		error_print();
		return -1;
	}

	for (i = 0; i < params->params_count; i++) {
		if (quic_varint_to_bytes(params->params[i].id, out, outlen) != 1
			|| quic_varint_to_bytes(params->params[i].datalen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		if (out && *out) {
			memcpy(*out, params->params[i].data, params->params[i].datalen);
			*out += params->params[i].datalen;
		}
		*outlen += params->params[i].datalen;
	}

	return 1;
}

int quic_transport_params_from_bytes(QUIC_TRANSPORT_PARAMS *params,
	const uint8_t **in, size_t *inlen)
{
	uint64_t id;
	uint64_t len;

	if (!params || !in || !inlen || (!*in && *inlen)) {
		error_print();
		return -1;
	}

	quic_transport_params_init(params);

	while (*inlen) {
		if (quic_varint_from_bytes(&id, in, inlen) != 1
			|| quic_varint_from_bytes(&len, in, inlen) != 1) {
			error_print();
			return -1;
		}
		if (len > *inlen || len > QUIC_TRANSPORT_PARAM_MAX_SIZE) {
			error_print();
			return -1;
		}
		if (quic_transport_params_add(params, id, *in, (size_t)len) != 1) {
			error_print();
			return -1;
		}
		*in += len;
		*inlen -= len;
	}

	return 1;
}

int quic_derive_initial_secrets(const uint8_t *dcid, size_t dcid_len, QUIC_INITIAL_SECRETS *secrets)
{
#if defined(ENABLE_SHA2)
	/* QUIC v1 Initial secrets always use SHA-256, independent of the TLS cipher suite. */
	const DIGEST *digest = DIGEST_sha256();
	uint8_t initial_secret[QUIC_INITIAL_SECRET_SIZE];
	size_t initial_secret_len;
	int ret = -1;

	if ((!dcid && dcid_len) || !secrets) {
		error_print();
		return -1;
	}

	if (hkdf_extract(digest, quic_v1_initial_salt, sizeof(quic_v1_initial_salt),
		dcid, dcid_len, initial_secret, &initial_secret_len) != 1
		|| initial_secret_len != QUIC_INITIAL_SECRET_SIZE
		|| tls13_hkdf_expand_label(digest, initial_secret, "client in", NULL, 0,
			QUIC_INITIAL_SECRET_SIZE, secrets->client_secret) != 1
		|| tls13_hkdf_expand_label(digest, initial_secret, "server in", NULL, 0,
			QUIC_INITIAL_SECRET_SIZE, secrets->server_secret) != 1) {
		error_print();
		goto end;
	}

	ret = 1;

end:
	gmssl_secure_clear(initial_secret, sizeof(initial_secret));
	return ret;
#else
	error_print();
	return -1;
#endif
}

int quic_derive_initial_client_keys(const QUIC_INITIAL_SECRETS *secrets, QUIC_INITIAL_KEYS *keys)
{
	if (!secrets) {
		error_print();
		return -1;
	}
	if (quic_derive_initial_keys(secrets->client_secret, keys) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int quic_derive_initial_server_keys(const QUIC_INITIAL_SECRETS *secrets, QUIC_INITIAL_KEYS *keys)
{
	if (!secrets) {
		error_print();
		return -1;
	}
	if (quic_derive_initial_keys(secrets->server_secret, keys) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int quic_derive_initial_keys(const uint8_t secret[QUIC_INITIAL_SECRET_SIZE], QUIC_INITIAL_KEYS *keys)
{
#if defined(ENABLE_SHA2)
	const DIGEST *digest = DIGEST_sha256();

	if (!secret || !keys) {
		error_print();
		return -1;
	}

	if (tls13_hkdf_expand_label(digest, secret, "quic key", NULL, 0,
		QUIC_INITIAL_KEY_SIZE, keys->key) != 1
		|| tls13_hkdf_expand_label(digest, secret, "quic iv", NULL, 0,
			QUIC_INITIAL_IV_SIZE, keys->iv) != 1
		|| tls13_hkdf_expand_label(digest, secret, "quic hp", NULL, 0,
			QUIC_INITIAL_HP_KEY_SIZE, keys->hp) != 1) {
		error_print();
		return -1;
	}

	return 1;
#else
	error_print();
	return -1;
#endif
}

int quic_packet_keys_derive(const DIGEST *digest, const uint8_t secret[32], int cipher_suite, QUIC_PACKET_KEYS *keys)
{
	if (!digest || !secret || !keys) {
		error_print();
		return -1;
	}
	keys->cipher_suite = cipher_suite;
	if (tls13_hkdf_expand_label(digest, secret, "quic key", NULL, 0, sizeof(keys->key), keys->key) != 1
		|| tls13_hkdf_expand_label(digest, secret, "quic iv", NULL, 0, sizeof(keys->iv), keys->iv) != 1
		|| tls13_hkdf_expand_label(digest, secret, "quic hp", NULL, 0, sizeof(keys->hp), keys->hp) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int quic_packet_keys_from_initial(const QUIC_INITIAL_KEYS *initial_keys, QUIC_PACKET_KEYS *keys)
{
	if (!initial_keys || !keys) {
		error_print();
		return -1;
	}
	keys->cipher_suite = TLS_cipher_aes_128_gcm_sha256;
	memcpy(keys->key, initial_keys->key, sizeof(keys->key));
	memcpy(keys->iv, initial_keys->iv, sizeof(keys->iv));
	memcpy(keys->hp, initial_keys->hp, sizeof(keys->hp));
	return 1;
}

int quic_packet_total_length(const uint8_t *packet, size_t packet_len, size_t *total_len)
{
	const uint8_t *p;
	size_t len;
	uint8_t dcid_len;
	uint8_t scid_len;
	uint64_t val;
	uint64_t payload_len;

	if (!packet || !total_len || !packet_len) {
		error_print();
		return -1;
	}
	if (!(packet[0] & 0x80)) {
		*total_len = packet_len;
		return 1;
	}
	if (packet_len < 7) {
		error_print();
		return -1;
	}
	p = packet + 5;
	len = packet_len - 5;
	dcid_len = *p++;
	len--;
	if (dcid_len > len) {
		error_print();
		return -1;
	}
	p += dcid_len;
	len -= dcid_len;
	if (!len) {
		error_print();
		return -1;
	}
	scid_len = *p++;
	len--;
	if (scid_len > len) {
		error_print();
		return -1;
	}
	p += scid_len;
	len -= scid_len;
	if (((packet[0] >> 4) & 0x03) == QUIC_packet_initial) {
		if (quic_varint_from_bytes(&val, &p, &len) != 1 || val > len) {
			error_print();
			return -1;
		}
		p += val;
		len -= val;
	}
	if (quic_varint_from_bytes(&payload_len, &p, &len) != 1 || payload_len > len) {
		error_print();
		return -1;
	}
	*total_len = (size_t)(p - packet) + (size_t)payload_len;
	return 1;
}

static int quic_packet_aead_encrypt(const QUIC_PACKET_KEYS *keys, const uint8_t nonce[12],
	const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t inlen, uint8_t *out)
{
	AES_KEY aes_key;
	SM4_KEY sm4_key;
	uint8_t ccm_plaintext[4096];
	const uint8_t *ccm_in = in;

	if (!keys || !nonce || !aad || !out || (!in && inlen)) {
		error_print();
		return -1;
	}
	switch (keys->cipher_suite) {
	case TLS_cipher_aes_128_gcm_sha256:
		if (aes_set_encrypt_key(&aes_key, keys->key, sizeof(keys->key)) != 1) {
			error_print();
			return -1;
		}
		return aes_gcm_encrypt(&aes_key, nonce, 12, aad, aad_len, in, inlen, out, 16, out + inlen);
	case TLS_cipher_aes_128_ccm_sha256:
#ifdef ENABLE_AES_CCM
		if (aes_set_encrypt_key(&aes_key, keys->key, sizeof(keys->key)) != 1) {
			error_print();
			return -1;
		}
		if (in == out && inlen) {
			if (inlen > sizeof(ccm_plaintext)) {
				error_print();
				return -1;
			}
			memcpy(ccm_plaintext, in, inlen);
			ccm_in = ccm_plaintext;
		}
		return aes_ccm_encrypt(&aes_key, nonce, 12, aad, aad_len, ccm_in, inlen, out, 16, out + inlen);
#else
		error_print();
		return -1;
#endif
	case TLS_cipher_sm4_gcm_sm3:
		sm4_set_encrypt_key(&sm4_key, keys->key);
		return sm4_gcm_encrypt(&sm4_key, nonce, 12, aad, aad_len, in, inlen, out, 16, out + inlen);
	case TLS_cipher_sm4_ccm_sm3:
#ifdef ENABLE_SM4_CCM
		sm4_set_encrypt_key(&sm4_key, keys->key);
		if (in == out && inlen) {
			if (inlen > sizeof(ccm_plaintext)) {
				error_print();
				return -1;
			}
			memcpy(ccm_plaintext, in, inlen);
			ccm_in = ccm_plaintext;
		}
		return sm4_ccm_encrypt(&sm4_key, nonce, 12, aad, aad_len, ccm_in, inlen, out, 16, out + inlen);
#else
		error_print();
		return -1;
#endif
	default:
		error_print();
		return -1;
	}
}

static int quic_packet_aead_decrypt(const QUIC_PACKET_KEYS *keys, const uint8_t nonce[12],
	const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t inlen, uint8_t *out)
{
	AES_KEY aes_key;
	SM4_KEY sm4_key;

	if (!keys || !nonce || !aad || !in || !out || inlen < 16) {
		error_print();
		return -1;
	}
	switch (keys->cipher_suite) {
	case TLS_cipher_aes_128_gcm_sha256:
		if (aes_set_encrypt_key(&aes_key, keys->key, sizeof(keys->key)) != 1) {
			error_print();
			return -1;
		}
		return aes_gcm_decrypt(&aes_key, nonce, 12, aad, aad_len, in, inlen - 16, in + inlen - 16, 16, out);
	case TLS_cipher_aes_128_ccm_sha256:
#ifdef ENABLE_AES_CCM
		if (aes_set_encrypt_key(&aes_key, keys->key, sizeof(keys->key)) != 1) {
			error_print();
			return -1;
		}
		return aes_ccm_decrypt(&aes_key, nonce, 12, aad, aad_len, in, inlen - 16, in + inlen - 16, 16, out);
#else
		error_print();
		return -1;
#endif
	case TLS_cipher_sm4_gcm_sm3:
		sm4_set_encrypt_key(&sm4_key, keys->key);
		return sm4_gcm_decrypt(&sm4_key, nonce, 12, aad, aad_len, in, inlen - 16, in + inlen - 16, 16, out);
	case TLS_cipher_sm4_ccm_sm3:
#ifdef ENABLE_SM4_CCM
		sm4_set_encrypt_key(&sm4_key, keys->key);
		return sm4_ccm_decrypt(&sm4_key, nonce, 12, aad, aad_len, in, inlen - 16, in + inlen - 16, 16, out);
#else
		error_print();
		return -1;
#endif
	default:
		error_print();
		return -1;
	}
}

static int quic_packet_hp_mask(const QUIC_PACKET_KEYS *keys, const uint8_t sample[16], uint8_t mask[16])
{
	AES_KEY aes_key;
	SM4_KEY sm4_key;

	if (!keys || !sample || !mask) {
		error_print();
		return -1;
	}
	switch (keys->cipher_suite) {
	case TLS_cipher_aes_128_gcm_sha256:
	case TLS_cipher_aes_128_ccm_sha256:
		if (aes_set_encrypt_key(&aes_key, keys->hp, sizeof(keys->hp)) != 1) {
			error_print();
			return -1;
		}
		aes_encrypt(&aes_key, sample, mask);
		return 1;
	case TLS_cipher_sm4_gcm_sm3:
	case TLS_cipher_sm4_ccm_sm3:
		sm4_set_encrypt_key(&sm4_key, keys->hp);
		sm4_encrypt(&sm4_key, sample, mask);
		return 1;
	default:
		error_print();
		return -1;
	}
}

int quic_long_packet_decrypt(const QUIC_PACKET_KEYS *keys, const uint8_t *packet, size_t packet_len, int expected_type, QUIC_DECRYPTED_PACKET *out)
{
	uint8_t buf[4096];
	const uint8_t *p;
	size_t len;
	uint64_t val;
	uint64_t long_packet_len;
	uint8_t dcid_len;
	uint8_t scid_len;
	size_t pn_offset;
	size_t pn_len;
	uint64_t packet_number = 0;
	uint8_t nonce[12];
	uint8_t mask[16];
	size_t aad_len;
	size_t ciphertext_len;
	size_t i;

	if (!keys || !packet || !out || packet_len > sizeof(buf) || packet_len < 7 || !(packet[0] & 0x80)) {
		error_print();
		return -1;
	}
	memset(out, 0, sizeof(*out));
	memcpy(buf, packet, packet_len);
	out->type = (buf[0] >> 4) & 0x03;
	if (out->type != expected_type) {
		return 0;
	}
	p = buf + 5;
	len = packet_len - 5;
	if (!len) return -1;
	dcid_len = *p++;
	len--;
	if (dcid_len > len || dcid_len > sizeof(out->dcid)) return -1;
	memcpy(out->dcid, p, dcid_len);
	out->dcid_len = dcid_len;
	p += dcid_len;
	len -= dcid_len;
	if (!len) return -1;
	scid_len = *p++;
	len--;
	if (scid_len > len || scid_len > sizeof(out->scid)) return -1;
	memcpy(out->scid, p, scid_len);
	out->scid_len = scid_len;
	p += scid_len;
	len -= scid_len;
	if (out->type == QUIC_packet_initial) {
		if (quic_varint_from_bytes(&val, &p, &len) != 1 || val > len) return -1;
		p += val;
		len -= val;
	}
	if (quic_varint_from_bytes(&long_packet_len, &p, &len) != 1 || long_packet_len > len) return -1;
	out->packet_len = (size_t)(p - buf) + (size_t)long_packet_len;
	pn_offset = (size_t)(p - buf);
	if (pn_offset + 4 + 16 > packet_len) return -1;
	if (quic_packet_hp_mask(keys, buf + pn_offset + 4, mask) != 1) return -1;
	buf[0] ^= mask[0] & 0x0f;
	pn_len = (buf[0] & 0x03) + 1;
	if (pn_len > long_packet_len) return -1;
	for (i = 0; i < pn_len; i++) {
		buf[pn_offset + i] ^= mask[i + 1];
		packet_number = (packet_number << 8) | buf[pn_offset + i];
	}
	memcpy(nonce, keys->iv, sizeof(nonce));
	for (i = 0; i < 8; i++) {
		nonce[sizeof(nonce) - 1 - i] ^= (uint8_t)(packet_number >> (8 * i));
	}
	aad_len = pn_offset + pn_len;
	ciphertext_len = (size_t)long_packet_len - pn_len;
	if (ciphertext_len < 16 || ciphertext_len - 16 > sizeof(out->plaintext)
		|| quic_packet_aead_decrypt(keys, nonce, buf, aad_len, buf + aad_len, ciphertext_len, out->plaintext) != 1) {
		error_print();
		return -1;
	}
	out->packet_number = packet_number;
	out->plaintext_len = ciphertext_len - 16;
	return 1;
}

int quic_long_packet_encrypt(const QUIC_PACKET_KEYS *keys, int type, const uint8_t *dcid, size_t dcid_len,
	const uint8_t *scid, size_t scid_len, uint64_t packet_number, const uint8_t *frames, size_t frames_len,
	uint8_t *packet, size_t *packet_len)
{
	uint8_t *p = packet;
	uint8_t *pn;
	uint8_t *payload;
	size_t len = 0;
	size_t payload_len = frames_len + 16;
	uint8_t nonce[12];
	uint8_t mask[16];
	size_t i;

	if (!keys || !dcid || dcid_len > 20 || !scid || scid_len > 20 || !frames || !packet || !packet_len) {
		error_print();
		return -1;
	}
	*p++ = (uint8_t)(0xc0 | (type << 4) | 0x03); len++;
	*p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x01; len += 4;
	*p++ = (uint8_t)dcid_len; len++;
	memcpy(p, dcid, dcid_len); p += dcid_len; len += dcid_len;
	*p++ = (uint8_t)scid_len; len++;
	memcpy(p, scid, scid_len); p += scid_len; len += scid_len;
	if (type == QUIC_packet_initial && quic_varint_to_bytes(0, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (quic_varint_to_bytes(4 + payload_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	pn = p;
	*p++ = (uint8_t)(packet_number >> 24);
	*p++ = (uint8_t)(packet_number >> 16);
	*p++ = (uint8_t)(packet_number >> 8);
	*p++ = (uint8_t)packet_number;
	len += 4;
	payload = p;
	memcpy(payload, frames, frames_len);
	memcpy(nonce, keys->iv, sizeof(nonce));
	for (i = 0; i < 8; i++) {
		nonce[sizeof(nonce) - 1 - i] ^= (uint8_t)(packet_number >> (8 * i));
	}
	if (quic_packet_aead_encrypt(keys, nonce, packet, len, payload, frames_len, payload) != 1) {
		error_print();
		return -1;
	}
	if (quic_packet_hp_mask(keys, payload, mask) != 1) return -1;
	packet[0] ^= mask[0] & 0x0f;
	for (i = 0; i < 4; i++) {
		pn[i] ^= mask[i + 1];
	}
	*packet_len = len + payload_len;
	return 1;
}

int quic_short_packet_decrypt(const QUIC_PACKET_KEYS *keys, const uint8_t *packet, size_t packet_len,
	const uint8_t *dcid, size_t dcid_len, QUIC_DECRYPTED_PACKET *out)
{
	uint8_t buf[4096];
	size_t pn_offset;
	size_t pn_len;
	uint64_t packet_number = 0;
	uint8_t nonce[12];
	uint8_t mask[16];
	size_t aad_len;
	size_t ciphertext_len;
	size_t i;

	if (!keys || !packet || !dcid || !out || packet_len > sizeof(buf) || packet_len < 1 + dcid_len + 4 + 16 || (packet[0] & 0x80)) {
		error_print();
		return -1;
	}
	memset(out, 0, sizeof(*out));
	memcpy(buf, packet, packet_len);
	out->type = QUIC_encryption_application;
	memcpy(out->dcid, dcid, dcid_len);
	out->dcid_len = dcid_len;
	pn_offset = 1 + dcid_len;
	if (quic_packet_hp_mask(keys, buf + pn_offset + 4, mask) != 1) return -1;
	buf[0] ^= mask[0] & 0x1f;
	pn_len = (buf[0] & 0x03) + 1;
	if (pn_offset + pn_len + 16 > packet_len) {
		error_print();
		return -1;
	}
	for (i = 0; i < pn_len; i++) {
		buf[pn_offset + i] ^= mask[i + 1];
		packet_number = (packet_number << 8) | buf[pn_offset + i];
	}
	memcpy(nonce, keys->iv, sizeof(nonce));
	for (i = 0; i < 8; i++) {
		nonce[sizeof(nonce) - 1 - i] ^= (uint8_t)(packet_number >> (8 * i));
	}
	aad_len = pn_offset + pn_len;
	ciphertext_len = packet_len - aad_len;
	if (ciphertext_len < 16 || ciphertext_len - 16 > sizeof(out->plaintext)
		|| quic_packet_aead_decrypt(keys, nonce, buf, aad_len, buf + aad_len, ciphertext_len, out->plaintext) != 1) {
		error_print();
		return -1;
	}
	out->packet_number = packet_number;
	out->packet_len = packet_len;
	out->plaintext_len = ciphertext_len - 16;
	return 1;
}

int quic_short_packet_encrypt(const QUIC_PACKET_KEYS *keys, const uint8_t *dcid, size_t dcid_len,
	uint64_t packet_number, const uint8_t *frames, size_t frames_len, uint8_t *packet, size_t *packet_len)
{
	uint8_t *pn;
	uint8_t *payload;
	size_t len = 0;
	size_t payload_len = frames_len + 16;
	uint8_t nonce[12];
	uint8_t mask[16];
	size_t i;

	if (!keys || !dcid || dcid_len > 20 || !frames || !packet || !packet_len) {
		error_print();
		return -1;
	}
	packet[len++] = 0x43;
	memcpy(packet + len, dcid, dcid_len);
	len += dcid_len;
	pn = packet + len;
	packet[len++] = (uint8_t)(packet_number >> 24);
	packet[len++] = (uint8_t)(packet_number >> 16);
	packet[len++] = (uint8_t)(packet_number >> 8);
	packet[len++] = (uint8_t)packet_number;
	payload = packet + len;
	memcpy(payload, frames, frames_len);
	memcpy(nonce, keys->iv, sizeof(nonce));
	for (i = 0; i < 8; i++) {
		nonce[sizeof(nonce) - 1 - i] ^= (uint8_t)(packet_number >> (8 * i));
	}
	if (quic_packet_aead_encrypt(keys, nonce, packet, len, payload, frames_len, payload) != 1) {
		error_print();
		return -1;
	}
	if (quic_packet_hp_mask(keys, payload, mask) != 1) return -1;
	packet[0] ^= mask[0] & 0x1f;
	for (i = 0; i < 4; i++) {
		pn[i] ^= mask[i + 1];
	}
	*packet_len = len + payload_len;
	return 1;
}

int quic_client_hello_to_bytes_ex(TLS_CONNECT *conn, const QUIC_TRANSPORT_PARAMS *params, uint8_t **out, size_t *outlen)
{
	const uint8_t *legacy_session_id = NULL;
	size_t legacy_session_id_len = 0;
	uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
	uint8_t *pexts = exts;
	size_t extslen = 0;

	if (!conn || !outlen) {
		error_print();
		return -1;
	}
	if (conn->recordlen) {
		return quic_tls_handshake_to_bytes(conn, QUIC_encryption_initial, out, outlen);
	}

	if (conn->verbose) tls_trace("build QUIC ClientHello\n");

	tls_record_set_protocol(conn->record, TLS_protocol_tls1);

	if (tls13_random_generate(conn->client_random) != 1) {
		error_print();
		return -1;
	}

	conn->session_id_len = 0;

	if (tls13_client_supported_versions_ext_to_bytes(conn->ctx->supported_versions,
		conn->ctx->supported_versions_cnt, &pexts, &extslen) != 1) {
		error_print();
		return -1;
	}

	if (conn->ctx->supported_groups_cnt) {
		if (tls_supported_groups_ext_to_bytes(conn->ctx->supported_groups,
			conn->ctx->supported_groups_cnt, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (conn->ctx->signature_algorithms_cnt) {
		if (tls_signature_algorithms_ext_to_bytes(conn->ctx->signature_algorithms,
			conn->ctx->signature_algorithms_cnt, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (conn->signature_algorithms_cert) {
		if (tls13_signature_algorithms_cert_ext_to_bytes(conn->ctx->signature_algorithms,
			conn->ctx->signature_algorithms_cnt, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (conn->certificate_authorities) {
		if (tls13_certificate_authorities_ext_to_bytes(conn->ctx->ca_names,
			conn->ctx->ca_names_len, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (conn->key_share) {
		size_t i;

		for (i = 0; i < conn->ctx->key_exchanges_cnt && i < conn->ctx->supported_groups_cnt; i++) {
			int curve_oid = tls_named_curve_oid(conn->ctx->supported_groups[i]);
			if (x509_key_generate(&conn->key_exchanges[i], OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
				error_print();
				return -1;
			}
		}
		conn->key_exchanges_cnt = i;
		if (tls13_key_share_client_hello_ext_to_bytes(conn->key_exchanges,
			conn->key_exchanges_cnt, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (conn->server_name) {
		if (tls_server_name_ext_to_bytes(conn->host_name, conn->host_name_len, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (conn->ctx->alpn_protocols_cnt) {
		if (tls_application_layer_protocol_negotiation_ext_to_bytes(conn->ctx->alpn_protocols,
			conn->ctx->alpn_protocols_cnt, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (params) {
		uint8_t transport_params[QUIC_TRANSPORT_PARAM_MAX_SIZE];
		uint8_t *ptransport_params = transport_params;
		size_t transport_params_len = 0;
		if (quic_transport_params_to_bytes(params, &ptransport_params, &transport_params_len) != 1
			|| tls_ext_to_bytes(TLS_extension_quic_transport_parameters,
				transport_params, transport_params_len, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (conn->key_exchange_modes & (TLS_KE_PSK_DHE|TLS_KE_PSK)) {
		if (tls13_psk_key_exchange_modes_ext_to_bytes(conn->key_exchange_modes, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (conn->status_request) {
		if (tls_client_status_request_ext_to_bytes(TLS_certificate_status_type_ocsp,
			conn->status_request_responder_id_list, conn->status_request_responder_id_list_len,
			conn->status_request_exts, conn->status_request_exts_len, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
		conn->status_request = 0;
	}

	if (conn->signed_certificate_timestamp) {
		if (tls_ext_to_bytes(TLS_extension_signed_certificate_timestamp, NULL, 0, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
		conn->signed_certificate_timestamp = 0;
	}

	if (conn->early_data) {
		if (tls_ext_to_bytes(TLS_extension_early_data, NULL, 0, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (conn->post_handshake_auth) {
		if (tls_ext_to_bytes(TLS_extension_post_handshake_auth, NULL, 0, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (conn->pre_shared_key) {
		uint8_t *ptruncated_exts = pexts;
		size_t truncated_extslen = extslen;
		uint8_t binders[256];
		uint8_t *pbinders = binders;
		size_t binderslen = 0;

		(void)pbinders;
		if (!conn->psk_identities_len || !conn->psk_keys_len || !conn->psk_cipher_suites_cnt) {
			error_print();
			return -1;
		}
		if (tls13_psk_binders_generate_empty(conn->psk_cipher_suites, conn->psk_cipher_suites_cnt, binders, &binderslen) != 1
			|| tls13_client_pre_shared_key_ext_to_bytes(conn->psk_identities, conn->psk_identities_len,
				binders, binderslen, &ptruncated_exts, &truncated_extslen) != 1) {
			error_print();
			return -1;
		}
		if (tls_record_set_handshake_client_hello(conn->record, &conn->recordlen,
			TLS_protocol_tls12, conn->client_random, legacy_session_id, legacy_session_id_len,
			conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt, exts, truncated_extslen) != 1) {
			error_print();
			return -1;
		}
		if (tls13_psk_binders_generate(conn->psk_cipher_suites, conn->psk_cipher_suites_cnt,
			conn->psk_identity_types, conn->psk_keys, conn->psk_keys_len,
			conn->record + TLS_RECORD_HEADER_SIZE, conn->recordlen - TLS_RECORD_HEADER_SIZE - 2 - binderslen,
			binders, &binderslen) != 1
			|| tls13_client_pre_shared_key_ext_to_bytes(conn->psk_identities, conn->psk_identities_len,
				binders, binderslen, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (tls_record_set_handshake_client_hello(conn->record, &conn->recordlen,
		TLS_protocol_tls12, conn->client_random, legacy_session_id, legacy_session_id_len,
		conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt, exts, extslen) != 1) {
		error_print();
		return -1;
	}

	if (conn->early_data) {
		if (tls13_generate_early_keys(conn) != 1) {
			error_print();
			return -1;
		}
	}

	if (quic_tls_handshake_to_bytes(conn, QUIC_encryption_initial, out, outlen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int quic_client_hello_to_bytes(TLS_CONNECT *conn, uint8_t **out, size_t *outlen)
{
	return quic_client_hello_to_bytes_ex(conn, NULL, out, outlen);
}

int quic_server_hello_to_bytes(TLS_CONNECT *conn, uint8_t **out, size_t *outlen)
{
	uint8_t exts[256];
	uint8_t *pexts = exts;
	size_t extslen = 0;

	if (!conn || !outlen) {
		error_print();
		return -1;
	}
	if (conn->recordlen) {
		return quic_tls_handshake_to_bytes(conn, QUIC_encryption_initial, out, outlen);
	}

	if (conn->verbose) tls_trace("build QUIC ServerHello\n");

	tls_record_set_protocol(conn->record, TLS_protocol_tls12);

	if (tls13_random_generate(conn->server_random) != 1) {
		error_print();
		return -1;
	}

	if (tls13_server_supported_versions_ext_to_bytes(conn->protocol, &pexts, &extslen) != 1) {
		error_print();
		return -1;
	}

	if (conn->key_exchange_modes & (TLS_KE_CERT_DHE|TLS_KE_PSK_DHE)) {
		int curve_oid;

		if (!conn->key_exchange_group) {
			error_print();
			return -1;
		}
		if ((curve_oid = tls_named_curve_oid(conn->key_exchange_group)) == OID_undef) {
			error_print();
			return -1;
		}
		if (x509_key_generate(&conn->key_exchanges[0], OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
			error_print();
			return -1;
		}
		conn->key_exchange_idx = 0;
		conn->key_exchanges_cnt = 1;
		if (tls13_key_share_server_hello_ext_to_bytes(&conn->key_exchanges[0], &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (conn->selected_psk_identity) {
		if (tls13_server_pre_shared_key_ext_to_bytes(conn->selected_psk_identity, &pexts, &extslen) != 1) {
			error_print();
			return -1;
		}
	}

	if (tls_record_set_handshake_server_hello(conn->record, &conn->recordlen,
		TLS_protocol_tls12, conn->server_random, conn->session_id, conn->session_id_len,
		conn->cipher_suite, exts, extslen) != 1) {
		error_print();
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + TLS_RECORD_HEADER_SIZE, conn->recordlen - TLS_RECORD_HEADER_SIZE) != 1
		|| tls13_generate_handshake_secrets(conn) != 1) {
		error_print();
		return -1;
	}
	tls13_generate_master_secret(conn);

	if (tls13_generate_server_handshake_keys(conn) != 1) {
		error_print();
		return -1;
	}
	if (!conn->early_data) {
		if (tls13_generate_client_handshake_keys(conn) != 1) {
			error_print();
			return -1;
		}
	}

	if (quic_tls_handshake_to_bytes(conn, QUIC_encryption_initial, out, outlen) != 1) {
		error_print();
		return -1;
	}

	tls_client_verify_update(&conn->client_verify_ctx, conn->record + TLS_RECORD_HEADER_SIZE, conn->recordlen - TLS_RECORD_HEADER_SIZE);
	tls_clean_record(conn);
	return 1;
}
