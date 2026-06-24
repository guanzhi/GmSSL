/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/pem.h>
#include <gmssl/sm2.h>
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>


#define SM2EXCH_RA_SIZE 65
#define SM2EXCH_RB_SIZE 65
#define SM2EXCH_CONFIRM_SIZE 32
#define SM2EXCH_RB_SB_SIZE (SM2EXCH_RB_SIZE + SM2EXCH_CONFIRM_SIZE)
#define SM2EXCH_SECRET_STATE_SIZE 65
#define SM2EXCH_MAX_SHARED_KEY_SIZE 1024
#define PEM_SM2_EXCH_PEER_RA "SM2 EXCHANGE PEER RA"

enum {
	SM2EXCH_FMT_BIN = 0,
	SM2EXCH_FMT_HEX = 1,
};

static const char *usage =
	"-stage init|respond|confirm|finish [options]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -stage init|respond|confirm|finish\n"
"                            SM2 key exchange stage\n"
"    -cert pem               Optional local SM2 certificate for checking against -key\n"
"    -pubkey pem             Optional local SM2 public key for checking against -key\n"
"    -key pem                Local SM2 private key in PEM format\n"
"    -pass str               Password to open local private key\n"
"    -peer_cert pem          Peer SM2 key exchange/encryption certificate in PEM format\n"
"    -peer_pubkey pem        Peer SM2 public key in PEM format\n"
"    -id str                 Local SM2 identity, '1234567812345678' by default\n"
"    -id_hex hex             Local SM2 identity in hex\n"
"    -peer_id str            Peer SM2 identity, '1234567812345678' by default\n"
"    -peer_id_hex hex        Peer SM2 identity in hex\n"
"    -in file | stdin        Input data for this stage\n"
"                            respond: RA, 65 bytes\n"
"                            confirm: RB || SB, 97 bytes\n"
"                            finish: SA, 32 bytes\n"
"    -out file | stdout      Output data to send to peer\n"
"                            init: RA, 65 bytes\n"
"                            respond: RB || SB, 97 bytes\n"
"                            confirm: SA, 32 bytes\n"
"    -exch_keyout pem        Output local ephemeral private key\n"
"    -exch_key pem           Input local ephemeral private key\n"
"    -exch_pass str          Password for local ephemeral private key\n"
"    -secret_state_out file\n"
"                            Output 65-byte secret_state point\n"
"    -secret_state file      Input 65-byte secret_state point\n"
"    -keylen num             Shared key length in bytes, 32 by default\n"
"    -keyout file            Output shared key\n"
"    -hex                    Encode input/output data in hex, default\n"
"    -bin                    Encode input/output data in binary\n"
"\n"
"Examples\n"
"\n"
"Public-key file workflow:\n"
"\n"
"    gmssl sm2keygen -pass P@ssw0rd -out alice.pem -pubout alicepub.pem\n"
"    gmssl sm2keygen -pass P@ssw0rd -out bob.pem -pubout bobpub.pem\n"
"    gmssl sm2exch -stage init \\\n"
"          -exch_keyout alice_ra.pem -exch_pass P@ssw0rd -out ra.hex\n"
"    gmssl sm2exch -stage respond \\\n"
"          -key bob.pem -pass P@ssw0rd -id Bob \\\n"
"          -peer_pubkey alicepub.pem -peer_id Alice -in ra.hex \\\n"
"          -exch_keyout bob_rb.pem -exch_pass P@ssw0rd \\\n"
"          -secret_state_out bob_secret_state.hex -out rb_sb.hex\n"
"    gmssl sm2exch -stage confirm \\\n"
"          -key alice.pem -pass P@ssw0rd -id Alice \\\n"
"          -peer_pubkey bobpub.pem -peer_id Bob \\\n"
"          -exch_key alice_ra.pem -exch_pass P@ssw0rd -in rb_sb.hex \\\n"
"          -keylen 48 -keyout alice_shared_key.hex -out sa.hex\n"
"    gmssl sm2exch -stage finish \\\n"
"          -key bob.pem -pass P@ssw0rd -id Bob \\\n"
"          -peer_pubkey alicepub.pem -peer_id Alice \\\n"
"          -exch_key bob_rb.pem -exch_pass P@ssw0rd \\\n"
"          -secret_state bob_secret_state.hex -in sa.hex \\\n"
"          -keylen 48 -keyout bob_shared_key.hex\n"
"\n"
"Certificate workflow:\n"
"\n"
"    gmssl sm2exch -stage respond \\\n"
"          -key bob_enc_key.pem -pass P@ssw0rd -id Bob \\\n"
"          -peer_cert alice_enc_cert.pem -peer_id Alice -in ra.hex \\\n"
"          -exch_keyout bob_rb.pem -exch_pass P@ssw0rd \\\n"
"          -secret_state_out bob_secret_state.hex -out rb_sb.hex\n"
"    gmssl sm2exch -stage confirm \\\n"
"          -key alice_enc_key.pem -pass P@ssw0rd -id Alice \\\n"
"          -peer_cert bob_enc_cert.pem -peer_id Bob \\\n"
"          -exch_key alice_ra.pem -exch_pass P@ssw0rd -in rb_sb.hex \\\n"
"          -keyout alice_shared_key.hex -out sa.hex\n"
"\n"
"Notes\n"
"\n"
"    -cert and -peer_cert read only the first certificate from the PEM file.\n"
"    If KeyUsage is present, the certificate must allow keyEncipherment or keyAgreement.\n"
"    RA, RB and secret_state are fixed 65-byte uncompressed SM2 points.\n"
"    The respond output is RB || SB, fixed 97 bytes.\n"
"    -hex and -bin affect RA, RB||SB, SA, secret_state and shared key files.\n"
"\n";

static int read_file(const char *file, uint8_t *buf, size_t *len, size_t maxlen)
{
	FILE *fp = stdin;
	size_t n;

	if (!buf || !len) {
		return -1;
	}
	if (file && !(fp = fopen(file, "rb"))) {
		return -1;
	}
	n = fread(buf, 1, maxlen + 1, fp);
	if (ferror(fp)) {
		if (file) fclose(fp);
		return -1;
	}
	if (file) fclose(fp);
	if (n > maxlen) {
		return -1;
	}
	*len = n;
	return 1;
}

static int write_file(const char *file, const uint8_t *buf, size_t len)
{
	FILE *fp = stdout;
	int ret = -1;

	if (!buf || !len) {
		return -1;
	}
	if (file && !(fp = fopen(file, "wb"))) {
		return -1;
	}
	if (fwrite(buf, 1, len, fp) == len) {
		ret = 1;
	}
	if (file) fclose(fp);
	return ret;
}

static int sm2exch_read_exact(const char *file, uint8_t *buf, size_t len);

static int sm2exch_write_data(const char *file, const uint8_t *buf, size_t len, int format)
{
	uint8_t *hexbuf = NULL;
	size_t i;
	int ret;

	if (format == SM2EXCH_FMT_BIN) {
		return write_file(file, buf, len);
	}
	if (!(hexbuf = malloc(len * 2))) {
		return -1;
	}
	for (i = 0; i < len; i++) {
		static const char *hex = "0123456789abcdef";
		hexbuf[i * 2] = (uint8_t)hex[buf[i] >> 4];
		hexbuf[i * 2 + 1] = (uint8_t)hex[buf[i] & 0x0f];
	}
	ret = write_file(file, hexbuf, len * 2);
	gmssl_secure_clear(hexbuf, len * 2);
	free(hexbuf);
	return ret;
}

static int sm2exch_read_data(const char *file, uint8_t *buf, size_t len, int format)
{
	uint8_t *in = NULL;
	uint8_t *hex = NULL;
	size_t inlen;
	size_t hexlen = 0;
	size_t outlen;
	size_t i;
	int ret = -1;

	if (format == SM2EXCH_FMT_BIN) {
		return sm2exch_read_exact(file, buf, len);
	}
	if (!(in = malloc(len * 2 + 64)) || !(hex = malloc(len * 2))) {
		goto end;
	}
	if (read_file(file, in, &inlen, len * 2 + 63) != 1) {
		goto end;
	}
	for (i = 0; i < inlen; i++) {
		if (in[i] == ' ' || in[i] == '\t' || in[i] == '\r' || in[i] == '\n') {
			continue;
		}
		if (hexlen >= len * 2) {
			goto end;
		}
		hex[hexlen++] = in[i];
	}
	if (hexlen != len * 2
		|| hex_to_bytes((char *)hex, hexlen, buf, &outlen) != 1
		|| outlen != len) {
		goto end;
	}
	ret = 1;
end:
	if (in) {
		gmssl_secure_clear(in, len * 2 + 64);
		free(in);
	}
	if (hex) {
		gmssl_secure_clear(hex, len * 2);
		free(hex);
	}
	return ret;
}

static int sm2exch_read_point(const char *file, uint8_t point[65], int format)
{
	if (sm2exch_read_data(file, point, 65, format) != 1) {
		return -1;
	}
	if (point[0] != 0x04) {
		return -1;
	}
	return 1;
}

static int sm2exch_read_exact(const char *file, uint8_t *buf, size_t len)
{
	size_t inlen;

	if (read_file(file, buf, &inlen, len) != 1 || inlen != len) {
		return -1;
	}
	return 1;
}

static int sm2exch_cert_check_key_usage(const uint8_t *cert, size_t certlen)
{
	int ret;
	int critical;
	const uint8_t *exts;
	size_t extslen;
	const uint8_t *val;
	size_t vlen;
	int bits;

	if (!cert || !certlen) {
		return -1;
	}
	if ((ret = x509_cert_get_exts(cert, certlen, &exts, &extslen)) < 0) {
		return -1;
	}
	if (ret == 0) {
		return 1;
	}
	if ((ret = x509_exts_get_ext_by_oid(exts, extslen, OID_ce_key_usage,
		&critical, &val, &vlen)) < 0) {
		return -1;
	}
	if (ret == 0) {
		return 1;
	}
	if (x509_key_usage_from_der(&bits, &val, &vlen) != 1
		|| asn1_length_is_zero(vlen) != 1) {
		return -1;
	}
	if ((bits & (X509_KU_KEY_ENCIPHERMENT | X509_KU_KEY_AGREEMENT)) == 0) {
		return 0;
	}
	return 1;
}

static int sm2exch_load_public_key(SM2_KEY *pub_key, const char *pubkeyfile,
	const char *certfile, const char *prog, const char *label)
{
	FILE *fp = NULL;
	uint8_t cert[4096];
	size_t certlen;
	X509_KEY x509_key;
	int ret;

	if (!pub_key || !prog || !label) {
		return -1;
	}
	if (pubkeyfile && certfile) {
		if (label[0]) {
			fprintf(stderr, "gmssl %s: options '-%s_pubkey' and '-%s_cert' conflict\n",
				prog, label, label);
		} else {
			fprintf(stderr, "gmssl %s: options '-pubkey' and '-cert' conflict\n", prog);
		}
		return -1;
	}
	if (pubkeyfile) {
		if (!(fp = fopen(pubkeyfile, "rb"))) {
			fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, pubkeyfile, strerror(errno));
			return -1;
		}
		ret = sm2_public_key_info_from_pem(pub_key, fp);
		fclose(fp);
		if (ret != 1) {
			fprintf(stderr, "gmssl %s: parse public key failed\n", prog);
			return -1;
		}
		return 1;
	}
	if (certfile) {
		if (!(fp = fopen(certfile, "rb"))) {
			fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, certfile, strerror(errno));
			return -1;
		}
		ret = x509_cert_from_pem(cert, &certlen, sizeof(cert), fp);
		fclose(fp);
		if (ret != 1
			|| x509_cert_get_subject_public_key(cert, certlen, &x509_key) != 1) {
			fprintf(stderr, "gmssl %s: parse certificate failed\n", prog);
			return -1;
		}
		if (x509_key.algor != OID_ec_public_key || x509_key.algor_param != OID_sm2) {
			fprintf(stderr, "gmssl %s: certificate public key is not SM2\n", prog);
			return -1;
		}
		ret = sm2exch_cert_check_key_usage(cert, certlen);
		if (ret < 0) {
			fprintf(stderr, "gmssl %s: certificate KeyUsage parse failure\n", prog);
			return -1;
		}
		if (ret == 0) {
			fprintf(stderr, "gmssl %s: certificate KeyUsage does not allow key exchange/encryption\n", prog);
			return -1;
		}
		*pub_key = x509_key.u.sm2_key;
		return 1;
	}

	if (label[0]) {
		fprintf(stderr, "gmssl %s: '-%s_pubkey' or '-%s_cert' option required\n",
			prog, label, label);
	} else {
		fprintf(stderr, "gmssl %s: '-pubkey' or '-cert' option required\n", prog);
	}
	return -1;
}

static int sm2exch_load_private_key(SM2_KEY *key, const char *keyfile,
	const char *pass, const char *prog)
{
	FILE *fp;
	int ret;

	if (!keyfile) {
		fprintf(stderr, "gmssl %s: '-key' option required\n", prog);
		return -1;
	}
	if (!pass) {
		fprintf(stderr, "gmssl %s: '-pass' option required\n", prog);
		return -1;
	}
	if (!(fp = fopen(keyfile, "rb"))) {
		fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, keyfile, strerror(errno));
		return -1;
	}
	ret = sm2_private_key_info_decrypt_from_pem(key, pass, fp);
	fclose(fp);
	if (ret != 1) {
		fprintf(stderr, "gmssl %s: private key decryption failure\n", prog);
		return -1;
	}
	return 1;
}

static int sm2exch_load_exch_key(SM2_KEY *key, uint8_t peer_ra[65],
	const char *keyfile, const char *pass, const char *prog)
{
	FILE *fp;
	int ret;
	size_t len;

	if (!keyfile) {
		fprintf(stderr, "gmssl %s: '-exch_key' option required\n", prog);
		return -1;
	}
	if (!pass) {
		fprintf(stderr, "gmssl %s: '-exch_pass' option required\n", prog);
		return -1;
	}
	if (!(fp = fopen(keyfile, "rb"))) {
		fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, keyfile, strerror(errno));
		return -1;
	}
	ret = sm2_private_key_info_decrypt_from_pem(key, pass, fp);
	if (ret != 1) {
		fprintf(stderr, "gmssl %s: ephemeral private key decryption failure\n", prog);
		goto end;
	}
	if (peer_ra) {
		if (pem_read(fp, PEM_SM2_EXCH_PEER_RA, peer_ra, &len, 65) != 1
			|| len != 65 || peer_ra[0] != 0x04) {
			fprintf(stderr, "gmssl %s: peer RA not found in exchange key\n", prog);
			ret = -1;
			goto end;
		}
	}
	ret = 1;
end:
	fclose(fp);
	return ret;
}

static int sm2exch_save_exch_key(const SM2_KEY *key, const char *keyfile,
	const char *pass, const uint8_t peer_ra[65], const char *prog)
{
	FILE *fp;
	int ret;

	if (!keyfile) {
		fprintf(stderr, "gmssl %s: '-exch_keyout' option required\n", prog);
		return -1;
	}
	if (!pass) {
		fprintf(stderr, "gmssl %s: '-exch_pass' option required\n", prog);
		return -1;
	}
	if (!(fp = fopen(keyfile, "wb"))) {
		fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, keyfile, strerror(errno));
		return -1;
	}
	ret = sm2_private_key_info_encrypt_to_pem(key, pass, fp);
	if (ret == 1 && peer_ra) {
		ret = pem_write(fp, PEM_SM2_EXCH_PEER_RA, peer_ra, 65);
	}
	fclose(fp);
	if (ret != 1) {
		fprintf(stderr, "gmssl %s: output ephemeral private key failed\n", prog);
		return -1;
	}
	return 1;
}

static int sm2exch_load_local_keys(SM2_KEY *key, const char *keyfile, const char *pass,
	const char *pubkeyfile, const char *certfile, const char *prog)
{
	SM2_KEY pub_key;

	if (sm2exch_load_private_key(key, keyfile, pass, prog) != 1) {
		return -1;
	}
	if (pubkeyfile || certfile) {
		if (sm2exch_load_public_key(&pub_key, pubkeyfile, certfile, prog, "") != 1) {
			return -1;
		}
		if (sm2_public_key_equ(key, &pub_key) != 1) {
			fprintf(stderr, "gmssl %s: private key does not match local public key/certificate\n", prog);
			return -1;
		}
	}
	return 1;
}

static int sm2exch_derive_key_from_secret_state(int is_initiator,
	const SM2_KEY *key, const char *id, size_t idlen,
	const SM2_KEY *peer_public_key, const char *peer_id, size_t peer_idlen,
	const uint8_t secret_state[65], uint8_t *shared_key, size_t shared_key_len)
{
	SM2_Z256_POINT point;
	uint8_t za[32];
	uint8_t zb[32];
	uint8_t kdf_input[128];
	int ret = -1;

	if (!key || !id || !peer_public_key || !peer_id
		|| !secret_state || !shared_key || !shared_key_len) {
		return -1;
	}
	if (sm2_z256_point_from_octets(&point, secret_state, 65) != 1) {
		return -1;
	}
	if (is_initiator) {
		if (sm2_compute_z(za, &key->public_key, id, idlen) != 1
			|| sm2_compute_z(zb, &peer_public_key->public_key, peer_id, peer_idlen) != 1) {
			goto end;
		}
	} else {
		if (sm2_compute_z(za, &peer_public_key->public_key, peer_id, peer_idlen) != 1
			|| sm2_compute_z(zb, &key->public_key, id, idlen) != 1) {
			goto end;
		}
	}
	sm2_z256_point_to_bytes(&point, kdf_input);
	memcpy(kdf_input + 64, za, sizeof(za));
	memcpy(kdf_input + 96, zb, sizeof(zb));
	if (sm2_kdf(kdf_input, sizeof(kdf_input), shared_key_len, shared_key) != 1
		|| mem_is_zero(shared_key, shared_key_len)) {
		goto end;
	}
	ret = 1;
end:
	gmssl_secure_clear(&point, sizeof(point));
	gmssl_secure_clear(za, sizeof(za));
	gmssl_secure_clear(zb, sizeof(zb));
	gmssl_secure_clear(kdf_input, sizeof(kdf_input));
	return ret;
}

static int sm2exch_stage_init(const char *exch_keyoutfile, const char *exch_pass,
	const char *outfile, int format, const char *prog)
{
	SM2_KEY exch_key;
	uint8_t ra[65];
	int ret = -1;

	if (sm2_key_generate(&exch_key) != 1
		|| sm2_z256_point_to_uncompressed_octets(&exch_key.public_key, ra) != 1
		|| sm2exch_save_exch_key(&exch_key, exch_keyoutfile, exch_pass, NULL, prog) != 1
		|| sm2exch_write_data(outfile, ra, sizeof(ra), format) != 1) {
		fprintf(stderr, "gmssl %s: init stage failure\n", prog);
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&exch_key, sizeof(exch_key));
	return ret;
}

static int sm2exch_stage_respond(const char *keyfile, const char *pass,
	const char *pubkeyfile, const char *certfile,
	const char *peer_pubkeyfile, const char *peer_certfile,
	const char *id, size_t idlen, const char *peer_id, size_t peer_idlen,
	const char *infile, const char *exch_keyoutfile, const char *exch_pass,
	const char *secret_stateoutfile, const char *outfile, size_t keylen,
	int format, const char *prog)
{
	SM2_KEY key;
	SM2_KEY peer_public_key;
	SM2_KEY exch_key;
	uint8_t ra[65];
	uint8_t rb[65];
	uint8_t secret_state[65];
	uint8_t shared_key[SM2EXCH_MAX_SHARED_KEY_SIZE];
	uint8_t sb[32];
	uint8_t rb_sb[97];
	int ret = -1;

	if (!secret_stateoutfile) {
		fprintf(stderr, "gmssl %s: '-secret_state_out' option required\n", prog);
		return -1;
	}
	if (sm2exch_load_local_keys(&key, keyfile, pass, pubkeyfile, certfile, prog) != 1
		|| sm2exch_load_public_key(&peer_public_key, peer_pubkeyfile, peer_certfile, prog, "peer") != 1
		|| sm2exch_read_point(infile, ra, format) != 1
		|| sm2_key_generate(&exch_key) != 1
		|| sm2_z256_point_to_uncompressed_octets(&exch_key.public_key, rb) != 1) {
		fprintf(stderr, "gmssl %s: respond stage input failure\n", prog);
		goto end;
	}
	if (sm2_key_exchange(0, &key, id, idlen, &peer_public_key, peer_id, peer_idlen,
			&exch_key, ra, secret_state, keylen, shared_key) != 1
		|| sm2_key_exchange_compute_confirm(0, &key, id, idlen,
			&peer_public_key, peer_id, peer_idlen,
			&exch_key, ra, secret_state, sb) != 1
		|| sm2exch_save_exch_key(&exch_key, exch_keyoutfile, exch_pass, ra, prog) != 1
		|| sm2exch_write_data(secret_stateoutfile, secret_state, sizeof(secret_state), format) != 1) {
		fprintf(stderr, "gmssl %s: respond stage failure\n", prog);
		goto end;
	}
	memcpy(rb_sb, rb, sizeof(rb));
	memcpy(rb_sb + sizeof(rb), sb, sizeof(sb));
	if (sm2exch_write_data(outfile, rb_sb, sizeof(rb_sb), format) != 1) {
		fprintf(stderr, "gmssl %s: output RB||SB failed : %s\n", prog, strerror(errno));
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&peer_public_key, sizeof(peer_public_key));
	gmssl_secure_clear(&exch_key, sizeof(exch_key));
	gmssl_secure_clear(secret_state, sizeof(secret_state));
	gmssl_secure_clear(shared_key, sizeof(shared_key));
	gmssl_secure_clear(sb, sizeof(sb));
	return ret;
}

static int sm2exch_stage_confirm(const char *keyfile, const char *pass,
	const char *pubkeyfile, const char *certfile,
	const char *peer_pubkeyfile, const char *peer_certfile,
	const char *id, size_t idlen, const char *peer_id, size_t peer_idlen,
	const char *exch_keyfile, const char *exch_pass, const char *infile,
	const char *secret_stateoutfile, const char *keyoutfile, const char *outfile,
	size_t keylen, int format, const char *prog)
{
	SM2_KEY key;
	SM2_KEY peer_public_key;
	SM2_KEY exch_key;
	uint8_t rb_sb[97];
	uint8_t secret_state[65];
	uint8_t shared_key[SM2EXCH_MAX_SHARED_KEY_SIZE];
	uint8_t sa[32];
	int vr;
	int ret = -1;

	if (!keyoutfile) {
		fprintf(stderr, "gmssl %s: '-keyout' option required\n", prog);
		return -1;
	}
	if (sm2exch_load_local_keys(&key, keyfile, pass, pubkeyfile, certfile, prog) != 1
		|| sm2exch_load_public_key(&peer_public_key, peer_pubkeyfile, peer_certfile, prog, "peer") != 1
		|| sm2exch_load_exch_key(&exch_key, NULL, exch_keyfile, exch_pass, prog) != 1
		|| sm2exch_read_data(infile, rb_sb, sizeof(rb_sb), format) != 1) {
		fprintf(stderr, "gmssl %s: confirm stage input failure\n", prog);
		goto end;
	}
	if (sm2_key_exchange(1, &key, id, idlen, &peer_public_key, peer_id, peer_idlen,
			&exch_key, rb_sb, secret_state, keylen, shared_key) != 1) {
		fprintf(stderr, "gmssl %s: key exchange failure\n", prog);
		goto end;
	}
	if ((vr = sm2_key_exchange_verify_confirm(1, &key, id, idlen,
		&peer_public_key, peer_id, peer_idlen, &exch_key,
		rb_sb, secret_state, rb_sb + SM2EXCH_RB_SIZE)) != 1) {
		fprintf(stderr, "gmssl %s: SB verification %s\n", prog, vr < 0 ? "failure" : "failed");
		goto end;
	}
	if (sm2_key_exchange_compute_confirm(1, &key, id, idlen,
		&peer_public_key, peer_id, peer_idlen, &exch_key,
		rb_sb, secret_state, sa) != 1
		|| sm2exch_write_data(keyoutfile, shared_key, keylen, format) != 1
		|| sm2exch_write_data(outfile, sa, sizeof(sa), format) != 1) {
		fprintf(stderr, "gmssl %s: confirm stage failure\n", prog);
		goto end;
	}
	if (secret_stateoutfile
		&& sm2exch_write_data(secret_stateoutfile, secret_state, sizeof(secret_state), format) != 1) {
		fprintf(stderr, "gmssl %s: output secret_state failed : %s\n", prog, strerror(errno));
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&peer_public_key, sizeof(peer_public_key));
	gmssl_secure_clear(&exch_key, sizeof(exch_key));
	gmssl_secure_clear(secret_state, sizeof(secret_state));
	gmssl_secure_clear(shared_key, sizeof(shared_key));
	gmssl_secure_clear(sa, sizeof(sa));
	return ret;
}

static int sm2exch_stage_finish(const char *keyfile, const char *pass,
	const char *pubkeyfile, const char *certfile,
	const char *peer_pubkeyfile, const char *peer_certfile,
	const char *id, size_t idlen, const char *peer_id, size_t peer_idlen,
	const char *exch_keyfile, const char *exch_pass, const char *secret_statefile,
	const char *infile, const char *keyoutfile, size_t keylen, int format,
	const char *prog)
{
	SM2_KEY key;
	SM2_KEY peer_public_key;
	SM2_KEY exch_key;
	uint8_t ra[65];
	uint8_t secret_state[65];
	uint8_t sa[32];
	uint8_t shared_key[SM2EXCH_MAX_SHARED_KEY_SIZE];
	int vr;
	int ret = -1;

	if (!secret_statefile) {
		fprintf(stderr, "gmssl %s: '-secret_state' option required\n", prog);
		return -1;
	}
	if (!keyoutfile) {
		fprintf(stderr, "gmssl %s: '-keyout' option required\n", prog);
		return -1;
	}
	if (sm2exch_load_local_keys(&key, keyfile, pass, pubkeyfile, certfile, prog) != 1
		|| sm2exch_load_public_key(&peer_public_key, peer_pubkeyfile, peer_certfile, prog, "peer") != 1
		|| sm2exch_load_exch_key(&exch_key, ra, exch_keyfile, exch_pass, prog) != 1
		|| sm2exch_read_point(secret_statefile, secret_state, format) != 1
		|| sm2exch_read_data(infile, sa, sizeof(sa), format) != 1) {
		fprintf(stderr, "gmssl %s: finish stage input failure\n", prog);
		goto end;
	}
	if ((vr = sm2_key_exchange_verify_confirm(0, &key, id, idlen,
		&peer_public_key, peer_id, peer_idlen, &exch_key,
		ra, secret_state, sa)) != 1) {
		fprintf(stderr, "gmssl %s: SA verification %s\n", prog, vr < 0 ? "failure" : "failed");
		goto end;
	}
	if (sm2exch_derive_key_from_secret_state(0, &key, id, idlen,
		&peer_public_key, peer_id, peer_idlen,
		secret_state, shared_key, keylen) != 1
		|| sm2exch_write_data(keyoutfile, shared_key, keylen, format) != 1) {
		fprintf(stderr, "gmssl %s: finish stage failure\n", prog);
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&peer_public_key, sizeof(peer_public_key));
	gmssl_secure_clear(&exch_key, sizeof(exch_key));
	gmssl_secure_clear(secret_state, sizeof(secret_state));
	gmssl_secure_clear(shared_key, sizeof(shared_key));
	return ret;
}

int sm2exch_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *stage = NULL;
	char *certfile = NULL;
	char *pubkeyfile = NULL;
	char *keyfile = NULL;
	char *pass = NULL;
	char *peer_certfile = NULL;
	char *peer_pubkeyfile = NULL;
	char *id = NULL;
	char *peer_id = NULL;
	char *id_hex = NULL;
	char *peer_id_hex = NULL;
	char id_buf[SM2_MAX_ID_LENGTH];
	size_t id_len = 0;
	char peer_id_buf[SM2_MAX_ID_LENGTH];
	size_t peer_id_len = 0;
	char *infile = NULL;
	char *outfile = NULL;
	char *exch_keyfile = NULL;
	char *exch_keyoutfile = NULL;
	char *exch_pass = NULL;
	char *secret_statefile = NULL;
	char *secret_stateoutfile = NULL;
	char *keyoutfile = NULL;
	size_t keylen = 32;
	int format = SM2EXCH_FMT_HEX;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n", prog, usage);
			printf("%s\n", options);
			return 0;
		} else if (!strcmp(*argv, "-stage")) {
			if (--argc < 1) goto bad;
			stage = *(++argv);
		} else if (!strcmp(*argv, "-cert")) {
			if (pubkeyfile) {
				fprintf(stderr, "gmssl %s: options '-cert' and '-pubkey' conflict\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			certfile = *(++argv);
		} else if (!strcmp(*argv, "-pubkey")) {
			if (certfile) {
				fprintf(stderr, "gmssl %s: options '-cert' and '-pubkey' conflict\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-peer_cert")) {
			if (peer_pubkeyfile) {
				fprintf(stderr, "gmssl %s: options '-peer_cert' and '-peer_pubkey' conflict\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			peer_certfile = *(++argv);
		} else if (!strcmp(*argv, "-peer_pubkey")) {
			if (peer_certfile) {
				fprintf(stderr, "gmssl %s: options '-peer_cert' and '-peer_pubkey' conflict\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			peer_pubkeyfile = *(++argv);
		} else if (!strcmp(*argv, "-id")) {
			if (id_hex) {
				fprintf(stderr, "gmssl %s: '-id' and '-id_hex' should not be used together\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			id = *(++argv);
			id_len = strlen(id);
		} else if (!strcmp(*argv, "-id_hex")) {
			if (id) {
				fprintf(stderr, "gmssl %s: '-id' and '-id_hex' should not be used together\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			id_hex = *(++argv);
			if (strlen(id_hex) > sizeof(id_buf) * 2
				|| hex_to_bytes(id_hex, strlen(id_hex), (uint8_t *)id_buf, &id_len) != 1) {
				fprintf(stderr, "gmssl %s: invalid '-id_hex' value\n", prog);
				goto end;
			}
			id = id_buf;
		} else if (!strcmp(*argv, "-peer_id")) {
			if (peer_id_hex) {
				fprintf(stderr, "gmssl %s: '-peer_id' and '-peer_id_hex' should not be used together\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			peer_id = *(++argv);
			peer_id_len = strlen(peer_id);
		} else if (!strcmp(*argv, "-peer_id_hex")) {
			if (peer_id) {
				fprintf(stderr, "gmssl %s: '-peer_id' and '-peer_id_hex' should not be used together\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			peer_id_hex = *(++argv);
			if (strlen(peer_id_hex) > sizeof(peer_id_buf) * 2
				|| hex_to_bytes(peer_id_hex, strlen(peer_id_hex), (uint8_t *)peer_id_buf, &peer_id_len) != 1) {
				fprintf(stderr, "gmssl %s: invalid '-peer_id_hex' value\n", prog);
				goto end;
			}
			peer_id = peer_id_buf;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
		} else if (!strcmp(*argv, "-exch_keyout")) {
			if (--argc < 1) goto bad;
			exch_keyoutfile = *(++argv);
		} else if (!strcmp(*argv, "-exch_key")) {
			if (--argc < 1) goto bad;
			exch_keyfile = *(++argv);
		} else if (!strcmp(*argv, "-exch_pass")) {
			if (--argc < 1) goto bad;
			exch_pass = *(++argv);
		} else if (!strcmp(*argv, "-secret_state_out")) {
			if (--argc < 1) goto bad;
			secret_stateoutfile = *(++argv);
		} else if (!strcmp(*argv, "-secret_state")) {
			if (--argc < 1) goto bad;
			secret_statefile = *(++argv);
		} else if (!strcmp(*argv, "-keylen")) {
			if (--argc < 1) goto bad;
			keylen = (size_t)atoi(*(++argv));
			if (keylen < 1 || keylen > SM2EXCH_MAX_SHARED_KEY_SIZE) {
				fprintf(stderr, "gmssl %s: invalid '-keylen' value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-keyout")) {
			if (--argc < 1) goto bad;
			keyoutfile = *(++argv);
		} else if (!strcmp(*argv, "-hex")) {
			format = SM2EXCH_FMT_HEX;
		} else if (!strcmp(*argv, "-bin")) {
			format = SM2EXCH_FMT_BIN;
		} else {
			fprintf(stderr, "gmssl %s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "gmssl %s: '%s' option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!stage) {
		fprintf(stderr, "gmssl %s: '-stage' option required\n", prog);
		goto end;
	}
	if (!id) {
		id = SM2_DEFAULT_ID;
		id_len = SM2_DEFAULT_ID_LENGTH;
	}
	if (!peer_id) {
		peer_id = SM2_DEFAULT_ID;
		peer_id_len = SM2_DEFAULT_ID_LENGTH;
	}

	if (!strcmp(stage, "init")) {
		ret = sm2exch_stage_init(exch_keyoutfile, exch_pass, outfile, format, prog);
	} else if (!strcmp(stage, "respond")) {
		ret = sm2exch_stage_respond(keyfile, pass, pubkeyfile, certfile,
			peer_pubkeyfile, peer_certfile, id, id_len, peer_id, peer_id_len,
			infile, exch_keyoutfile, exch_pass, secret_stateoutfile,
			outfile, keylen, format, prog);
	} else if (!strcmp(stage, "confirm")) {
		ret = sm2exch_stage_confirm(keyfile, pass, pubkeyfile, certfile,
			peer_pubkeyfile, peer_certfile, id, id_len, peer_id, peer_id_len,
			exch_keyfile, exch_pass, infile, secret_stateoutfile,
			keyoutfile, outfile, keylen, format, prog);
	} else if (!strcmp(stage, "finish")) {
		ret = sm2exch_stage_finish(keyfile, pass, pubkeyfile, certfile,
			peer_pubkeyfile, peer_certfile, id, id_len, peer_id, peer_id_len,
			exch_keyfile, exch_pass, secret_statefile, infile,
			keyoutfile, keylen, format, prog);
	} else {
		fprintf(stderr, "gmssl %s: invalid '-stage' value\n", prog);
		goto end;
	}

end:
	return ret == 0 ? 0 : 1;
}
