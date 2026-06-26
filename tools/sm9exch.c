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
#include <gmssl/sm9.h>
#include "passwd.h"


#define SM9EXCH_R_SIZE 32
#define SM9EXCH_RA_SIZE 65
#define SM9EXCH_RB_SIZE 65
#define SM9EXCH_CONFIRM_SIZE 32
#define SM9EXCH_RB_SB_SIZE (SM9EXCH_RB_SIZE + SM9EXCH_CONFIRM_SIZE)
#define SM9EXCH_EXCH_KEY_SIZE (SM9EXCH_R_SIZE + SM9EXCH_RB_SIZE)
#define SM9EXCH_EXCH_KEY_WITH_PEER_R_SIZE (SM9EXCH_EXCH_KEY_SIZE + SM9EXCH_RA_SIZE)
#define SM9EXCH_MAX_SHARED_KEY_SIZE 1024
#define PEM_SM9_EXCH_KEY "SM9 EXCHANGE PRIVATE KEY"

enum {
	SM9EXCH_FMT_BIN = 0,
	SM9EXCH_FMT_HEX = 1,
};

static const char *usage =
	"-stage init|respond|confirm|finish [options]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -stage init|respond|confirm|finish\n"
"                            SM9 key exchange stage\n"
"    -pubmaster pem          SM9 exchange master public key in PEM format\n"
"    -key pem                Local SM9 exchange private key in PEM format\n"
"    -pass str               Password to open local private key, prompt if not given\n"
"    -id str                 Local SM9 identity\n"
"    -id_hex hex             Local SM9 identity in hex\n"
"    -peer_id str            Peer SM9 identity\n"
"    -peer_id_hex hex        Peer SM9 identity in hex\n"
"    -in file | stdin        Input data for this stage\n"
"                            respond: RA, 65 bytes\n"
"                            confirm: RB || SB, 97 bytes\n"
"                            finish: SA, 32 bytes\n"
"    -out file | stdout      Output data to send to peer\n"
"                            init: RA, 65 bytes\n"
"                            respond: RB || SB, 97 bytes\n"
"                            confirm: SA, 32 bytes\n"
"    -exch_keyout pem        Output local ephemeral exchange state r||R in PEM format\n"
"    -exch_key pem           Input local ephemeral exchange state r||R in PEM format\n"
"    -keylen num             Shared key length in bytes, 32 by default\n"
"    -keyout file            Output shared key\n"
"    -hex                    Encode input/output data in hex, default\n"
"    -bin                    Encode input/output data in binary\n"
"\n"
"Examples\n"
"\n"
"    gmssl sm9setup -alg sm9encrypt -pass P@ssw0rd \\\n"
"          -out sm9_msk.pem -pubout sm9_mpk.pem\n"
"    gmssl sm9keygen -alg sm9keyagreement -in sm9_msk.pem -inpass P@ssw0rd \\\n"
"          -id Alice -out alice.pem -outpass 123456\n"
"    gmssl sm9keygen -alg sm9keyagreement -in sm9_msk.pem -inpass P@ssw0rd \\\n"
"          -id Bob -out bob.pem -outpass 123456\n"
"    gmssl sm9exch -stage init \\\n"
"          -pubmaster sm9_mpk.pem -peer_id Bob \\\n"
"          -exch_keyout alice_ra.pem -out ra.hex\n"
"    gmssl sm9exch -stage respond \\\n"
"          -pubmaster sm9_mpk.pem -key bob.pem -pass 123456 -id Bob \\\n"
"          -peer_id Alice -in ra.hex \\\n"
"          -exch_keyout bob_rb.pem -out rb_sb.hex\n"
"    gmssl sm9exch -stage confirm \\\n"
"          -pubmaster sm9_mpk.pem -key alice.pem -pass 123456 -id Alice \\\n"
"          -peer_id Bob -exch_key alice_ra.pem -in rb_sb.hex \\\n"
"          -keylen 48 -keyout alice_shared_key.hex -out sa.hex\n"
"    gmssl sm9exch -stage finish \\\n"
"          -pubmaster sm9_mpk.pem -key bob.pem -pass 123456 -id Bob \\\n"
"          -peer_id Alice -exch_key bob_rb.pem \\\n"
"          -in sa.hex -keylen 48 -keyout bob_shared_key.hex\n"
"\n"
"Notes\n"
"\n"
"    RA and RB are fixed 65-byte uncompressed SM9 curve points.\n"
"    The respond output is RB || SB, fixed 97 bytes.\n"
"    The ephemeral exchange state contains secret scalar r, public point R and optional peer point.\n"
"    -hex and -bin affect RA, RB||SB, SA and shared key files.\n"
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

static int sm9exch_read_exact(const char *file, uint8_t *buf, size_t len);

static int sm9exch_write_data(const char *file, const uint8_t *buf, size_t len, int format)
{
	uint8_t *hexbuf = NULL;
	size_t i;
	int ret;

	if (format == SM9EXCH_FMT_BIN) {
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

static int sm9exch_read_data(const char *file, uint8_t *buf, size_t len, int format)
{
	uint8_t *in = NULL;
	uint8_t *hex = NULL;
	size_t inlen;
	size_t hexlen = 0;
	size_t outlen;
	size_t i;
	int ret = -1;

	if (format == SM9EXCH_FMT_BIN) {
		return sm9exch_read_exact(file, buf, len);
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

static int sm9exch_read_exact(const char *file, uint8_t *buf, size_t len)
{
	size_t inlen;

	if (read_file(file, buf, &inlen, len) != 1 || inlen != len) {
		return -1;
	}
	return 1;
}

static int sm9exch_read_point_file(const char *file, SM9_Z256_POINT *point, int format)
{
	uint8_t buf[65];

	if (sm9exch_read_data(file, buf, sizeof(buf), format) != 1
		|| sm9_z256_point_from_uncompressed_octets(point, buf) != 1
		|| !sm9_z256_point_is_on_curve(point)) {
		return -1;
	}
	return 1;
}

static int sm9exch_load_master_public_key(SM9_EXCH_MASTER_KEY *mpk,
	const char *mpkfile, const char *prog)
{
	FILE *fp = NULL;
	int ret = -1;

	if (!mpkfile) {
		fprintf(stderr, "gmssl %s: '-pubmaster' option required\n", prog);
		return -1;
	}
	if (!(fp = fopen(mpkfile, "rb"))) {
		fprintf(stderr, "gmssl %s: open master public key failed : %s\n", prog, strerror(errno));
		goto end;
	}
	if (sm9_enc_master_public_key_from_pem(mpk, fp) != 1) {
		fprintf(stderr, "gmssl %s: parse master public key failed\n", prog);
		goto end;
	}
	ret = 1;
end:
	if (fp) fclose(fp);
	return ret;
}

static int sm9exch_load_private_key(SM9_EXCH_KEY *key, const char *keyfile,
	const char *pass, const SM9_EXCH_MASTER_KEY *mpk, const char *prog)
{
	FILE *fp = NULL;
	int ret = -1;

	if (!keyfile) {
		fprintf(stderr, "gmssl %s: '-key' option required\n", prog);
		return -1;
	}
	if (!pass) {
		fprintf(stderr, "gmssl %s: '-pass' option required\n", prog);
		return -1;
	}
	if (!(fp = fopen(keyfile, "rb"))) {
		fprintf(stderr, "gmssl %s: open private key failed : %s\n", prog, strerror(errno));
		goto end;
	}
	if (sm9_enc_key_info_decrypt_from_pem(key, pass, fp) != 1) {
		fprintf(stderr, "gmssl %s: parse private key failed\n", prog);
		goto end;
	}
	if (mpk && sm9_z256_point_equ(&key->Ppube, &mpk->Ppube) != 1) {
		fprintf(stderr, "gmssl %s: private key does not match master public key\n", prog);
		goto end;
	}
	ret = 1;
end:
	if (fp) fclose(fp);
	return ret;
}

static int sm9exch_generate_R(const SM9_EXCH_MASTER_KEY *mpk,
	const char *peer_id, size_t peer_idlen, sm9_z256_t r, SM9_Z256_POINT *R)
{
	if (!mpk || !peer_id || !peer_idlen || !r || !R) {
		return -1;
	}
	if (peer_idlen > SM9_MAX_ID_SIZE) {
		return -1;
	}
	sm9_z256_hash1(r, peer_id, peer_idlen, SM9_HID_EXCH);
	sm9_z256_point_mul(R, r, sm9_z256_generator());
	sm9_z256_point_add(R, R, &mpk->Ppube);

	do {
		if (sm9_z256_rand_range(r, sm9_z256_order()) != 1) {
			return -1;
		}
	} while (sm9_z256_is_zero(r));

	sm9_z256_point_mul(R, r, R);
	return 1;
}

static int sm9exch_save_exch_key(const sm9_z256_t r, const SM9_Z256_POINT *R,
	const SM9_Z256_POINT *peer_R, const char *keyfile, const char *prog)
{
	FILE *fp = NULL;
	uint8_t buf[SM9EXCH_EXCH_KEY_WITH_PEER_R_SIZE];
	size_t len = SM9EXCH_EXCH_KEY_SIZE;
	int ret = -1;

	if (!keyfile) {
		fprintf(stderr, "gmssl %s: '-exch_keyout' option required\n", prog);
		return -1;
	}
	sm9_z256_to_bytes(r, buf);
	if (sm9_z256_point_to_uncompressed_octets(R, buf + SM9EXCH_R_SIZE) != 1) {
		goto end;
	}
	if (peer_R) {
		if (sm9_z256_point_to_uncompressed_octets(peer_R, buf + SM9EXCH_EXCH_KEY_SIZE) != 1) {
			goto end;
		}
		len = SM9EXCH_EXCH_KEY_WITH_PEER_R_SIZE;
	}
	if (!(fp = fopen(keyfile, "wb"))) {
		fprintf(stderr, "gmssl %s: open output exchange key failed : %s\n", prog, strerror(errno));
		goto end;
	}
	if (pem_write(fp, PEM_SM9_EXCH_KEY, buf, len) != 1) {
		fprintf(stderr, "gmssl %s: output exchange key failed\n", prog);
		goto end;
	}
	ret = 1;
end:
	gmssl_secure_clear(buf, sizeof(buf));
	if (fp) fclose(fp);
	return ret;
}

static int sm9exch_load_exch_key(sm9_z256_t r, SM9_Z256_POINT *R,
	SM9_Z256_POINT *peer_R, const char *keyfile, const char *prog)
{
	FILE *fp = NULL;
	uint8_t buf[SM9EXCH_EXCH_KEY_WITH_PEER_R_SIZE];
	size_t len;
	int ret = -1;

	if (!keyfile) {
		fprintf(stderr, "gmssl %s: '-exch_key' option required\n", prog);
		return -1;
	}
	if (!(fp = fopen(keyfile, "rb"))) {
		fprintf(stderr, "gmssl %s: open exchange key failed : %s\n", prog, strerror(errno));
		goto end;
	}
	if (pem_read(fp, PEM_SM9_EXCH_KEY, buf, &len, sizeof(buf)) != 1
		|| (len != SM9EXCH_EXCH_KEY_SIZE && len != SM9EXCH_EXCH_KEY_WITH_PEER_R_SIZE)) {
		fprintf(stderr, "gmssl %s: parse exchange key failed\n", prog);
		goto end;
	}
	sm9_z256_from_bytes(r, buf);
	if (sm9_z256_is_zero(r)
		|| sm9_z256_point_from_uncompressed_octets(R, buf + SM9EXCH_R_SIZE) != 1
		|| !sm9_z256_point_is_on_curve(R)) {
		fprintf(stderr, "gmssl %s: invalid exchange key\n", prog);
		goto end;
	}
	if (peer_R) {
		if (len != SM9EXCH_EXCH_KEY_WITH_PEER_R_SIZE
			|| sm9_z256_point_from_uncompressed_octets(peer_R, buf + SM9EXCH_EXCH_KEY_SIZE) != 1
			|| !sm9_z256_point_is_on_curve(peer_R)) {
			fprintf(stderr, "gmssl %s: peer exchange point not found in exchange key\n", prog);
			goto end;
		}
	}
	ret = 1;
end:
	gmssl_secure_clear(buf, sizeof(buf));
	if (fp) fclose(fp);
	return ret;
}

static int sm9exch_stage_init(const char *mpkfile, const char *peer_id,
	size_t peer_idlen, const char *exch_keyoutfile, const char *outfile,
	int format, const char *prog)
{
	SM9_EXCH_MASTER_KEY mpk;
	SM9_Z256_POINT R;
	sm9_z256_t r;
	uint8_t ra[65];
	int ret = -1;

	if (!peer_id) {
		fprintf(stderr, "gmssl %s: '-peer_id' option required\n", prog);
		return -1;
	}
	if (sm9exch_load_master_public_key(&mpk, mpkfile, prog) != 1
		|| sm9exch_generate_R(&mpk, peer_id, peer_idlen, r, &R) != 1
		|| sm9_z256_point_to_uncompressed_octets(&R, ra) != 1
		|| sm9exch_save_exch_key(r, &R, NULL, exch_keyoutfile, prog) != 1
		|| sm9exch_write_data(outfile, ra, sizeof(ra), format) != 1) {
		fprintf(stderr, "gmssl %s: init stage failure\n", prog);
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&mpk, sizeof(mpk));
	gmssl_secure_clear(&R, sizeof(R));
	gmssl_secure_clear(r, sizeof(r));
	return ret;
}

static int sm9exch_stage_respond(const char *mpkfile, const char *keyfile,
	const char *pass, const char *id, size_t idlen,
	const char *peer_id, size_t peer_idlen, const char *infile,
	const char *exch_keyoutfile, const char *outfile, size_t keylen,
	int format, const char *prog)
{
	SM9_EXCH_MASTER_KEY mpk;
	SM9_EXCH_KEY key;
	SM9_Z256_POINT ra;
	SM9_Z256_POINT rb;
	sm9_z256_t r;
	uint8_t rb_octets[65];
	uint8_t shared_key[SM9EXCH_MAX_SHARED_KEY_SIZE];
	uint8_t sb[32];
	uint8_t rb_sb[97];
	int ret = -1;

	if (!id) {
		fprintf(stderr, "gmssl %s: '-id' option required\n", prog);
		return -1;
	}
	if (!peer_id) {
		fprintf(stderr, "gmssl %s: '-peer_id' option required\n", prog);
		return -1;
	}
	if (sm9exch_load_master_public_key(&mpk, mpkfile, prog) != 1
		|| sm9exch_load_private_key(&key, keyfile, pass, &mpk, prog) != 1
		|| sm9exch_read_point_file(infile, &ra, format) != 1
		|| sm9exch_generate_R(&mpk, peer_id, peer_idlen, r, &rb) != 1
		|| sm9_z256_point_to_uncompressed_octets(&rb, rb_octets) != 1) {
		fprintf(stderr, "gmssl %s: respond stage input failure\n", prog);
		goto end;
	}
	if (sm9_key_exchange(0, &mpk, &key, id, idlen, peer_id, peer_idlen,
			r, &rb, &ra, keylen, shared_key) != 1
		|| sm9_key_exchange_compute_confirm(0, &mpk, &key, id, idlen,
			peer_id, peer_idlen, r, &rb, &ra, sb) != 1
		|| sm9exch_save_exch_key(r, &rb, &ra, exch_keyoutfile, prog) != 1) {
		fprintf(stderr, "gmssl %s: respond stage failure\n", prog);
		goto end;
	}
	memcpy(rb_sb, rb_octets, sizeof(rb_octets));
	memcpy(rb_sb + sizeof(rb_octets), sb, sizeof(sb));
	if (sm9exch_write_data(outfile, rb_sb, sizeof(rb_sb), format) != 1) {
		fprintf(stderr, "gmssl %s: output RB||SB failed : %s\n", prog, strerror(errno));
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&mpk, sizeof(mpk));
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&ra, sizeof(ra));
	gmssl_secure_clear(&rb, sizeof(rb));
	gmssl_secure_clear(r, sizeof(r));
	gmssl_secure_clear(shared_key, sizeof(shared_key));
	gmssl_secure_clear(sb, sizeof(sb));
	return ret;
}

static int sm9exch_stage_confirm(const char *mpkfile, const char *keyfile,
	const char *pass, const char *id, size_t idlen,
	const char *peer_id, size_t peer_idlen, const char *exch_keyfile,
	const char *infile, const char *keyoutfile, const char *outfile,
	size_t keylen, int format, const char *prog)
{
	SM9_EXCH_MASTER_KEY mpk;
	SM9_EXCH_KEY key;
	SM9_Z256_POINT ra;
	SM9_Z256_POINT rb;
	sm9_z256_t r;
	uint8_t rb_sb[97];
	uint8_t shared_key[SM9EXCH_MAX_SHARED_KEY_SIZE];
	uint8_t sa[32];
	int vr;
	int ret = -1;

	if (!id) {
		fprintf(stderr, "gmssl %s: '-id' option required\n", prog);
		return -1;
	}
	if (!peer_id) {
		fprintf(stderr, "gmssl %s: '-peer_id' option required\n", prog);
		return -1;
	}
	if (!keyoutfile) {
		fprintf(stderr, "gmssl %s: '-keyout' option required\n", prog);
		return -1;
	}
	if (sm9exch_load_master_public_key(&mpk, mpkfile, prog) != 1
		|| sm9exch_load_private_key(&key, keyfile, pass, &mpk, prog) != 1
		|| sm9exch_load_exch_key(r, &ra, NULL, exch_keyfile, prog) != 1
		|| sm9exch_read_data(infile, rb_sb, sizeof(rb_sb), format) != 1
		|| sm9_z256_point_from_uncompressed_octets(&rb, rb_sb) != 1
		|| !sm9_z256_point_is_on_curve(&rb)) {
		fprintf(stderr, "gmssl %s: confirm stage input failure\n", prog);
		goto end;
	}
	if (sm9_key_exchange(1, &mpk, &key, id, idlen, peer_id, peer_idlen,
			r, &ra, &rb, keylen, shared_key) != 1) {
		fprintf(stderr, "gmssl %s: key exchange failure\n", prog);
		goto end;
	}
	if ((vr = sm9_key_exchange_verify_confirm(1, &mpk, &key, id, idlen,
		peer_id, peer_idlen, r, &ra, &rb, rb_sb + SM9EXCH_RB_SIZE)) != 1) {
		fprintf(stderr, "gmssl %s: SB verification %s\n", prog, vr < 0 ? "failure" : "failed");
		goto end;
	}
	if (sm9_key_exchange_compute_confirm(1, &mpk, &key, id, idlen,
		peer_id, peer_idlen, r, &ra, &rb, sa) != 1
		|| sm9exch_write_data(keyoutfile, shared_key, keylen, format) != 1
		|| sm9exch_write_data(outfile, sa, sizeof(sa), format) != 1) {
		fprintf(stderr, "gmssl %s: confirm stage failure\n", prog);
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&mpk, sizeof(mpk));
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&ra, sizeof(ra));
	gmssl_secure_clear(&rb, sizeof(rb));
	gmssl_secure_clear(r, sizeof(r));
	gmssl_secure_clear(shared_key, sizeof(shared_key));
	gmssl_secure_clear(sa, sizeof(sa));
	return ret;
}

static int sm9exch_stage_finish(const char *mpkfile, const char *keyfile,
	const char *pass, const char *id, size_t idlen,
	const char *peer_id, size_t peer_idlen, const char *exch_keyfile,
	const char *infile, const char *keyoutfile, size_t keylen, int format,
	const char *prog)
{
	SM9_EXCH_MASTER_KEY mpk;
	SM9_EXCH_KEY key;
	SM9_Z256_POINT ra;
	SM9_Z256_POINT rb;
	sm9_z256_t r;
	uint8_t sa[32];
	uint8_t shared_key[SM9EXCH_MAX_SHARED_KEY_SIZE];
	int vr;
	int ret = -1;

	if (!id) {
		fprintf(stderr, "gmssl %s: '-id' option required\n", prog);
		return -1;
	}
	if (!peer_id) {
		fprintf(stderr, "gmssl %s: '-peer_id' option required\n", prog);
		return -1;
	}
	if (!keyoutfile) {
		fprintf(stderr, "gmssl %s: '-keyout' option required\n", prog);
		return -1;
	}
	if (sm9exch_load_master_public_key(&mpk, mpkfile, prog) != 1
		|| sm9exch_load_private_key(&key, keyfile, pass, &mpk, prog) != 1
		|| sm9exch_load_exch_key(r, &rb, &ra, exch_keyfile, prog) != 1
		|| sm9exch_read_data(infile, sa, sizeof(sa), format) != 1) {
		fprintf(stderr, "gmssl %s: finish stage input failure\n", prog);
		goto end;
	}
	if ((vr = sm9_key_exchange_verify_confirm(0, &mpk, &key, id, idlen,
		peer_id, peer_idlen, r, &rb, &ra, sa)) != 1) {
		fprintf(stderr, "gmssl %s: SA verification %s\n", prog, vr < 0 ? "failure" : "failed");
		goto end;
	}
	if (sm9_key_exchange(0, &mpk, &key, id, idlen, peer_id, peer_idlen,
		r, &rb, &ra, keylen, shared_key) != 1
		|| sm9exch_write_data(keyoutfile, shared_key, keylen, format) != 1) {
		fprintf(stderr, "gmssl %s: finish stage failure\n", prog);
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&mpk, sizeof(mpk));
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&ra, sizeof(ra));
	gmssl_secure_clear(&rb, sizeof(rb));
	gmssl_secure_clear(r, sizeof(r));
	gmssl_secure_clear(shared_key, sizeof(shared_key));
	return ret;
}

int sm9exch_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *stage = NULL;
	char *mpkfile = NULL;
	char *keyfile = NULL;
	char *pass = NULL;
	char passbuf[GMSSL_PASSWORD_MAX_SIZE] = {0};
	char *id = NULL;
	char *peer_id = NULL;
	char *id_hex = NULL;
	char *peer_id_hex = NULL;
	char id_buf[SM9_MAX_ID_SIZE];
	size_t id_len = 0;
	char peer_id_buf[SM9_MAX_ID_SIZE];
	size_t peer_id_len = 0;
	char *infile = NULL;
	char *outfile = NULL;
	char *exch_keyfile = NULL;
	char *exch_keyoutfile = NULL;
	char *keyoutfile = NULL;
	size_t keylen = 32;
	int format = SM9EXCH_FMT_HEX;

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
		} else if (!strcmp(*argv, "-pubmaster")) {
			if (--argc < 1) goto bad;
			mpkfile = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
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
		} else if (!strcmp(*argv, "-keylen")) {
			if (--argc < 1) goto bad;
			keylen = (size_t)atoi(*(++argv));
			if (keylen < 1 || keylen > SM9EXCH_MAX_SHARED_KEY_SIZE) {
				fprintf(stderr, "gmssl %s: invalid '-keylen' value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-keyout")) {
			if (--argc < 1) goto bad;
			keyoutfile = *(++argv);
		} else if (!strcmp(*argv, "-hex")) {
			format = SM9EXCH_FMT_HEX;
		} else if (!strcmp(*argv, "-bin")) {
			format = SM9EXCH_FMT_BIN;
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
	if (id && id_len > SM9_MAX_ID_SIZE) {
		fprintf(stderr, "gmssl %s: local identity too long\n", prog);
		goto end;
	}
	if (peer_id && peer_id_len > SM9_MAX_ID_SIZE) {
		fprintf(stderr, "gmssl %s: peer identity too long\n", prog);
		goto end;
	}

	if (!strcmp(stage, "init")) {
		ret = sm9exch_stage_init(mpkfile, peer_id, peer_id_len,
			exch_keyoutfile, outfile, format, prog);
	} else if (!strcmp(stage, "respond")) {
		if (keyfile && gmssl_tool_get_password(prog, "Password to open private key",
			keyfile, &pass, passbuf, sizeof(passbuf)) != 1) {
			goto end;
		}
		ret = sm9exch_stage_respond(mpkfile, keyfile, pass, id, id_len,
			peer_id, peer_id_len, infile, exch_keyoutfile,
			outfile, keylen, format, prog);
	} else if (!strcmp(stage, "confirm")) {
		if (keyfile && gmssl_tool_get_password(prog, "Password to open private key",
			keyfile, &pass, passbuf, sizeof(passbuf)) != 1) {
			goto end;
		}
		ret = sm9exch_stage_confirm(mpkfile, keyfile, pass, id, id_len,
			peer_id, peer_id_len, exch_keyfile, infile,
			keyoutfile, outfile, keylen, format, prog);
	} else if (!strcmp(stage, "finish")) {
		if (keyfile && gmssl_tool_get_password(prog, "Password to open private key",
			keyfile, &pass, passbuf, sizeof(passbuf)) != 1) {
			goto end;
		}
		ret = sm9exch_stage_finish(mpkfile, keyfile, pass, id, id_len,
			peer_id, peer_id_len, exch_keyfile, infile,
			keyoutfile, keylen, format, prog);
	} else {
		fprintf(stderr, "gmssl %s: invalid '-stage' value\n", prog);
		goto end;
	}

end:
	gmssl_secure_clear(passbuf, sizeof(passbuf));
	return ret == 0 ? 0 : 1;
}
