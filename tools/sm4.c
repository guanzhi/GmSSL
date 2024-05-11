/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/mem.h>
#include <gmssl/sm4.h>
#include <gmssl/sm4_cbc_sm3_hmac.h>
#include <gmssl/sm4_ctr_sm3_hmac.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>


enum {
	SM4_MODE_ECB = 1,
	SM4_MODE_CBC,
	SM4_MODE_CFB,
	SM4_MODE_OFB,
	SM4_MODE_CTR,
	SM4_MODE_XTS,
	SM4_MODE_CCM,
	SM4_MODE_GCM,
	SM4_MODE_CBC_SM3_HMAC,
	SM4_MODE_CTR_SM3_HMAC,
};

static uint8_t *read_content(FILE *infp, size_t *outlen, const char *prog)
{
	const size_t INITIAL_BUFFER_SIZE = 4096;
	const size_t MAX_BUFFER_SIZE = 512 * 1024 * 1024;
	uint8_t *buffer = NULL;
	size_t buffer_size = INITIAL_BUFFER_SIZE;
	size_t total_read = 0;

	if (!(buffer = (uint8_t *)malloc(INITIAL_BUFFER_SIZE))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		return NULL;
	}

	while (1) {
		size_t bytes_read;

		if (total_read == buffer_size) {
			uint8_t *new_buffer;

			if (buffer_size >= MAX_BUFFER_SIZE) {
				fprintf(stderr, "%s: input too long, should be less than %zu\n", prog, MAX_BUFFER_SIZE);
				free(buffer);
				return NULL;
			}
			buffer_size = buffer_size * 2;
			if (buffer_size > MAX_BUFFER_SIZE) {
				buffer_size = MAX_BUFFER_SIZE;
			}

			if (!(new_buffer = (uint8_t *)realloc(buffer, buffer_size))) {
				fprintf(stderr, "%s: realloc failure\n", prog);
				free(buffer);
				return NULL;
			}
			buffer = new_buffer;
		}

		bytes_read = fread(buffer + total_read, 1, buffer_size - total_read, infp);
		total_read += bytes_read;

		if (feof(infp)) {
			break;
		}

		if (ferror(infp)) {
			fprintf(stderr, "%s: fread error\n", prog);
			perror("error reading input");
			free(buffer);
			return NULL;
		}
	}

	*outlen = total_read;

	return buffer;
}

#ifdef ENABLE_SM4_CCM
static int sm4_ccm_crypt(const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, size_t taglen, FILE *infp, FILE *outfp, int enc,
	const char *prog)
{
	int ret = -1;
	SM4_KEY sm4_key;
	uint8_t *inbuf = NULL;
	uint8_t *outbuf = NULL;
	size_t inlen, outlen;
	uint8_t *tag;

	if (keylen != 16) {
		error_print();
		return -1;
	}
	if (ivlen < SM4_CCM_MIN_IV_SIZE || ivlen > SM4_CCM_MAX_IV_SIZE) {
		fprintf(stderr, "%s: invalid SM4-CCM IV length, should be in [%d, %d]\n",
			prog, SM4_CCM_MIN_IV_SIZE, SM4_CCM_MAX_IV_SIZE);
		return -1;
	}
	if (taglen < SM4_CCM_MIN_TAG_SIZE || taglen > SM4_CCM_MAX_TAG_SIZE) {
		fprintf(stderr, "%s: invalid SM4-CCM MAC tag length, should be in [%d, %d]\n",
			prog, SM4_CCM_MIN_TAG_SIZE, SM4_CCM_MAX_TAG_SIZE);
		return -1;
	}
	if (enc < 0) {
		error_print();
		return -1;
	}

	sm4_set_encrypt_key(&sm4_key, key);

	if (!(inbuf = read_content(infp, &inlen, prog))) {
		goto end;
	}

	if (enc) {
		outlen = inlen + taglen;
		if (!(outbuf = (uint8_t *)malloc(outlen))) {
			fprintf(stderr, "%s: malloc failure\n", prog);
			goto end;
		}
		tag = outbuf + inlen;
		if (sm4_ccm_encrypt(&sm4_key, iv, ivlen, aad, aadlen, inbuf, inlen, outbuf, taglen, tag) != 1) {
			error_print();
			goto end;
		}
	} else {
		if (inlen < taglen) {
			fprintf(stderr, "%s: input length (%zu bytes) shorter than tag length (%zu bytes)\n",
				prog, inlen, taglen);
			goto end;
		}
		outlen = inlen - taglen;
		tag = inbuf + inlen - taglen;
		if (!(outbuf = (uint8_t *)malloc(outlen))) {
			fprintf(stderr, "%s: malloc failure\n", prog);
			goto end;
		}
		if (sm4_ccm_decrypt(&sm4_key, iv, ivlen, aad, aadlen, inbuf, inlen - taglen,
			tag, taglen, outbuf) != 1) {
			error_print();
			goto end;
		}
	}

	if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
		fprintf(stderr, "%s: fwrite error\n", prog);
		goto end;
	}

	ret = 1;

end:
	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
	if (inbuf) free(inbuf);
	if (outbuf) free(outbuf);
	return ret;
}
#endif


static const char *usage =
	"(-cbc|-ctr|-gcm|-cbc_sm3_hmac|-ctr_sm3_hmac)"
	" {-encrypt|-decrypt} -key hex -iv hex"
	" [-aad str| -aad_hex hex] [-taglen num] [-in file] [-out file]";

static const char *options =
"Options\n"
"\n"
"  Modes\n"
"\n"
"    -ecb                ECB mode\n"
"    -cbc                CBC mode with padding, need 16-byte key and 16-byte iv\n"
"    -cfb                CFB mode with padding, need 16-byte key and 16-byte iv\n"
"    -ofb                OFB mode with padding, need 16-byte key and 16-byte iv\n"
"    -ctr                CTR mode, need 16-byte key and 16-byte iv\n"
"    -ccm                CCM mode, need 16-byte key and any iv length\n"
"    -gcm                GCM mode, need 16-byte key and any iv length\n"
"    -cbc_sm3_hmac       CBC mode with padding and HMAC-SM3 (encrypt-then-mac), need 48-byte key and 16-byte iv\n"
"    -ctr_sm3_hmac       CTR mode with HMAC-SM3 (entrypt-then-mac), need 48-byte key and 16-byte iv\n"
"    -xts                XTS mode\n"
"\n"
"    -encrypt            Encrypt\n"
"    -decrypt            Decrypt\n"
"    -key hex            Symmetric key in HEX format\n"
"    -iv hex             IV in HEX format\n"
"    -aad str            Authenticated-only message\n"
"    -aad_hex hex        Authenticated-only data in HEX format\n"
"    -in file | stdin    Input data\n"
"    -out file | stdout  Output data\n"
"\n"
"Examples"
"\n"
"  echo \"hello\" | gmssl sm4 -gcm -encrypt -key 11223344556677881122334455667788 -iv 112233445566778811223344 -out ciphertext.bin\n"
"  gmssl sm4 -gcm -decrypt -key 11223344556677881122334455667788 -iv 112233445566778811223344 -in ciphertext.bin\n"
"\n"
"  echo \"hello\" | gmssl sm4 -cbc_sm3_hmac -encrypt \\\n"
"                       -key 112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788 \\\n"
"                       -iv 11223344556677881122334455667788 -out ciphertext.bin\n"
"  gmssl sm4 -cbc_sm3_hmac -decrypt \\\n"
"                       -key 112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788 \\\n"
"                       -iv 11223344556677881122334455667788 -in ciphertext.bin\n"
"\n";

int sm4_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];

	char *keyhex = NULL;
	char *ivhex = NULL;
	uint8_t *aad = NULL;
	uint8_t *aad_buf = NULL;
	size_t aadlen = 0;

	char *infile = NULL;
	char *outfile = NULL;
	uint8_t key[48];
	uint8_t iv[SM4_GCM_MAX_IV_SIZE];
	size_t keylen = 0;
	size_t ivlen = 0;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	int mode = 0;
	int enc = -1;
	int rv;

	union {
#ifdef ENABLE_SM4_ECB
		SM4_ECB_CTX ecb;
#endif
		SM4_CBC_CTX cbc;
#ifdef ENABLE_SM4_CFB
		SM4_CFB_CTX cfb;
#endif
#ifdef ENABLE_SM4_OFB
		SM4_OFB_CTX ofb;
#endif
		SM4_CTR_CTX ctr;
#ifdef ENABLE_SM4_XTS
		SM4_XTS_CTX xts;
#endif
		SM4_GCM_CTX gcm;
		SM4_CBC_SM3_HMAC_CTX cbc_sm3_hmac;
		SM4_CTR_SM3_HMAC_CTX ctr_sm3_hmac;
	} sm4_ctx;


	uint8_t inbuf[4096];
	size_t inlen;

	uint8_t outbuf[41960];
	size_t outlen;

	int taglen = -1;
	int xts_data_unit_size = 0;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, usage);
			printf("%s\n", options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyhex = *(++argv);
			if (strlen(keyhex) > sizeof(key) * 2) {
				fprintf(stderr, "%s: invalid key length\n", prog);
				goto end;
			}
			if (hex_to_bytes(keyhex, strlen(keyhex), key, &keylen) != 1) {
				fprintf(stderr, "%s: invalid key hex digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-iv")) {
			if (--argc < 1) goto bad;
			ivhex = *(++argv);
			if (strlen(ivhex) > sizeof(iv) * 2) {
				fprintf(stderr, "%s: IV length too long\n", prog);
				goto end;
			}
			if (hex_to_bytes(ivhex, strlen(ivhex), iv, &ivlen) != 1) {
				fprintf(stderr, "%s: invalid IV hex digits\n", prog);
				goto end;
			}

		} else if (!strcmp(*argv, "-encrypt")) {
			if (enc == 0) {
				fprintf(stderr, "%s: `-encrypt` `-decrypt` should not be used together\n", prog);
				goto end;
			}
			enc = 1;
		} else if (!strcmp(*argv, "-decrypt")) {
			if (enc == 1) {
				fprintf(stderr, "%s: `-encrypt` `-decrypt` should not be used together\n", prog);
				goto end;
			}
			enc = 0;


		} else if (!strcmp(*argv, "-cbc")) {
			if (mode) goto bad;
			mode = SM4_MODE_CBC;
		} else if (!strcmp(*argv, "-ctr")) {
			if (mode) goto bad;
			mode = SM4_MODE_CTR;
		} else if (!strcmp(*argv, "-cbc_sm3_hmac")) {
			if (mode) goto bad;
			mode = SM4_MODE_CBC_SM3_HMAC;
		} else if (!strcmp(*argv, "-ctr_sm3_hmac")) {
			if (mode) goto bad;
			mode = SM4_MODE_CTR_SM3_HMAC;
		} else if (!strcmp(*argv, "-gcm")) {
			if (mode) goto bad;
			mode = SM4_MODE_GCM;
		} else if (!strcmp(*argv, "-ecb")) {
			if (mode) goto bad;
			mode = SM4_MODE_ECB;
		} else if (!strcmp(*argv, "-cfb")) {
			if (mode) goto bad;
			mode = SM4_MODE_CFB;
		} else if (!strcmp(*argv, "-ofb")) {
			if (mode) goto bad;
			mode = SM4_MODE_OFB;
		} else if (!strcmp(*argv, "-ccm")) {
			if (mode) goto bad;
			mode = SM4_MODE_CCM;
		} else if (!strcmp(*argv, "-xts")) {
			if (mode) goto bad;
			mode = SM4_MODE_XTS;

		} else if (!strcmp(*argv, "-aad")) {
			if (--argc < 1) goto bad;
			if (aad) {
				fprintf(stderr, "%s: `-aad` or `aad_hex` has been specified\n", prog);
				goto bad;
			}
			aad = (uint8_t *)(*(++argv));
			aadlen = strlen((char *)aad);
		} else if (!strcmp(*argv, "-aad_hex")) {
			if (--argc < 1) goto bad;
			if (aad) {
				fprintf(stderr, "%s: `-aad` or `aad_hex` has been specified\n", prog);
				goto bad;
			}
			aad = (uint8_t *)(*(++argv));
			if (!(aad_buf = malloc(strlen((char *)aad)/2 + 1))) {
				fprintf(stderr, "%s: malloc failure\n", prog);
				goto end;
			}
			if (hex_to_bytes((char *)aad, strlen((char *)aad), aad_buf, &aadlen) != 1) {
				fprintf(stderr, "%s: `-aad_hex` invalid HEX format argument\n", prog);
				goto end;
			}
			aad = aad_buf;
		} else if (!strcmp(*argv, "-taglen")) {
			if (--argc < 1) goto bad;
			taglen = atoi(*(++argv));
			if (taglen < 0 || taglen > 32) {
				fprintf(stderr, "%s: `-taglen` invalid integer argument\n", prog);
				goto end;
			}

		} else if (!strcmp(*argv, "-xts_data_unit_size")) {
			if (--argc < 1) goto bad;
			xts_data_unit_size = atoi(*(++argv));
			// FIXME: malloc outbuf for XTS
			if (xts_data_unit_size > sizeof(outbuf) - 1024) {
				error_print();
				goto end;
			}
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "%s: illegal option `%s`\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "%s: `%s` option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!mode) {
		fprintf(stderr, "%s: mode not assigned, `-cbc`, `-ctr`, `-gcm`, `-cbc_sm3_hmac` or `-ctr_sm3_hmac` required\n", prog);
		goto end;
	}
	if (!keyhex) {
		fprintf(stderr, "%s: option `-key` missing\n", prog);
		goto end;
	}
	/*
	if (!ivhex) {
		fprintf(stderr, "%s: option `-iv` missing\n", prog);
		goto end;
	}
	*/


	// check if mode is supported
	switch (mode) {
#ifdef ENABLE_SM4_ECB
	case SM4_MODE_ECB:
#endif
	case SM4_MODE_CBC:
#ifdef ENABLE_SM4_CFB
	case SM4_MODE_CFB:
#endif
#ifdef ENABLE_SM4_OFB
	case SM4_MODE_OFB:
#endif
	case SM4_MODE_CTR:
#ifdef ENABLE_SM4_CCM
	case SM4_MODE_CCM:
#endif
	case SM4_MODE_GCM:
#ifdef ENABLE_SM4_XTS
	case SM4_MODE_XTS:
#endif
	case SM4_MODE_CBC_SM3_HMAC:
	case SM4_MODE_CTR_SM3_HMAC:
		break;
	default:
		fprintf(stderr, "%s: mode is not supported\n", prog);
		goto end;
	}

	// check key length
	switch (mode) {
	case SM4_MODE_ECB:
	case SM4_MODE_CBC:
	case SM4_MODE_CFB:
	case SM4_MODE_OFB:
	case SM4_MODE_CTR:
	case SM4_MODE_CCM:
	case SM4_MODE_GCM:
		if (keylen != 16) {
			fprintf(stderr, "%s: invalid key length, should be 32 hex digits\n", prog);
			goto end;
		}
		break;
	case SM4_MODE_XTS:
		if (keylen != 32) {
			fprintf(stderr, "%s: invalid key length, should be 64 hex digits\n", prog);
			goto end;
		}
		break;
	case SM4_MODE_CBC_SM3_HMAC:
	case SM4_MODE_CTR_SM3_HMAC:
		if (keylen != 48) {
			fprintf(stderr, "%s: invalid key length, should be 96 hex digits\n", prog);
			goto end;
		}
		break;
	}

	// check iv length
	switch (mode) {
	case SM4_MODE_ECB:
		if (ivlen != 0) {
			fprintf(stderr, "%s: ECB mode need no IV\n", prog);
			goto end;
		}
		break;
	case SM4_MODE_CBC:
	case SM4_MODE_CFB:
	case SM4_MODE_OFB:
	case SM4_MODE_CTR:
	case SM4_MODE_CBC_SM3_HMAC:
	case SM4_MODE_CTR_SM3_HMAC:
		if (ivlen != 16) {
			fprintf(stderr, "%s: invalid IV length, should be 32 hex digits\n", prog);
			goto end;
		}
		break;
	}

	// check aad
	switch (mode) {
	case SM4_MODE_ECB:
	case SM4_MODE_CBC:
	case SM4_MODE_CFB:
	case SM4_MODE_OFB:
	case SM4_MODE_CTR:
	case SM4_MODE_XTS:
		if (aad) {
			fprintf(stderr, "%s: specified mode does not support `-aad` nor `-aad_hex`\n", prog);
			goto end;
		}
		break;
	}

	// encrypt/decrypt
	if (mode == SM4_MODE_CTR) {
		if (sm4_ctr_encrypt_init(&sm4_ctx.ctr, key, iv) != 1) {
			error_print();
			goto end;
		}
		while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
			if (sm4_ctr_encrypt_update(&sm4_ctx.ctr, inbuf, inlen, outbuf, &outlen) != 1) {
				error_print();
				goto end;
			}
			if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
				fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
				goto end;
			}
		}
		if (sm4_ctr_encrypt_finish(&sm4_ctx.ctr, outbuf, &outlen) != 1) {
			error_print();
			goto end;
		}
		if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}

		ret = 0;
		goto end;
	}

	if (enc < 0) {
		fprintf(stderr, "%s: option -encrypt or -decrypt should be set\n", prog);
		goto end;
	}

#ifdef ENABLE_SM4_CCM
	if (mode == SM4_MODE_CCM) {
		if (sm4_ccm_crypt(key, keylen, iv, ivlen, aad, aadlen, taglen, infp, outfp, enc, prog) != 1) {
			goto end;
		}
	}
#endif


	if (enc) {
		switch (mode) {
#ifdef ENABLE_SM4_ECB
		case SM4_MODE_ECB: rv = sm4_ecb_encrypt_init(&sm4_ctx.ecb, key); break;
#endif
		case SM4_MODE_CBC: rv = sm4_cbc_encrypt_init(&sm4_ctx.cbc, key, iv); break;
#ifdef ENABLE_SM4_CFB
		case SM4_MODE_CFB: rv = sm4_cfb_encrypt_init(&sm4_ctx.cfb, 16, key, iv); break;
#endif
#ifdef ENABLE_SM4_OFB
		case SM4_MODE_OFB: rv = sm4_ofb_encrypt_init(&sm4_ctx.ofb, key, iv); break;
#endif
#ifdef ENABLE_SM4_XTS
		case SM4_MODE_XTS: rv = sm4_xts_encrypt_init(&sm4_ctx.xts, key, iv, xts_data_unit_size); break;
#endif
		case SM4_MODE_GCM: rv = sm4_gcm_encrypt_init(&sm4_ctx.gcm, key, keylen, iv, ivlen, aad, aadlen, GHASH_SIZE); break;
		case SM4_MODE_CBC_SM3_HMAC: rv = sm4_cbc_sm3_hmac_encrypt_init(&sm4_ctx.cbc_sm3_hmac, key, iv, aad, aadlen); break;
		case SM4_MODE_CTR_SM3_HMAC: rv = sm4_ctr_sm3_hmac_encrypt_init(&sm4_ctx.ctr_sm3_hmac, key, iv, aad, aadlen); break;
		}
		if (rv != 1) {
			error_print();
			goto end;
		}

		while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
			switch (mode) {
#ifdef ENABLE_SM4_ECB
			case SM4_MODE_ECB: rv = sm4_ecb_encrypt_update(&sm4_ctx.ecb, inbuf, inlen, outbuf, &outlen); break;
#endif
			case SM4_MODE_CBC: rv = sm4_cbc_encrypt_update(&sm4_ctx.cbc, inbuf, inlen, outbuf, &outlen); break;
#ifdef ENABLE_SM4_CFB
			case SM4_MODE_CFB: rv = sm4_cfb_encrypt_update(&sm4_ctx.cfb, inbuf, inlen, outbuf, &outlen); break;
#endif
#ifdef ENABLE_SM4_OFB
			case SM4_MODE_OFB: rv = sm4_ofb_encrypt_update(&sm4_ctx.ofb, inbuf, inlen, outbuf, &outlen); break;
#endif
#ifdef ENABLE_SM4_XTS
			case SM4_MODE_XTS: rv = sm4_xts_encrypt_update(&sm4_ctx.xts, inbuf, inlen, outbuf, &outlen); break;
#endif
			case SM4_MODE_GCM: rv = sm4_gcm_encrypt_update(&sm4_ctx.gcm, inbuf, inlen, outbuf, &outlen); break;
			case SM4_MODE_CBC_SM3_HMAC: rv = sm4_cbc_sm3_hmac_encrypt_update(&sm4_ctx.cbc_sm3_hmac, inbuf, inlen, outbuf, &outlen); break;
			case SM4_MODE_CTR_SM3_HMAC: rv = sm4_ctr_sm3_hmac_encrypt_update(&sm4_ctx.ctr_sm3_hmac, inbuf, inlen, outbuf, &outlen); break;
			}
			if (rv != 1) {
				error_print();
				goto end;
			}
			if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
				fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
				goto end;
			}
		}

		switch (mode) {
#ifdef ENABLE_SM4_ECB
		case SM4_MODE_ECB: rv = sm4_ecb_encrypt_finish(&sm4_ctx.ecb, outbuf, &outlen); break;
#endif
		case SM4_MODE_CBC: rv = sm4_cbc_encrypt_finish(&sm4_ctx.cbc, outbuf, &outlen); break;
#ifdef ENABLE_SM4_CFB
		case SM4_MODE_CFB: rv = sm4_cfb_encrypt_finish(&sm4_ctx.cfb, outbuf, &outlen); break;
#endif
#ifdef ENABLE_SM4_OFB
		case SM4_MODE_OFB: rv = sm4_ofb_encrypt_finish(&sm4_ctx.ofb, outbuf, &outlen); break;
#endif
#ifdef ENABLE_SM4_XTS
		case SM4_MODE_XTS: rv = sm4_xts_encrypt_finish(&sm4_ctx.xts, outbuf, &outlen); break;
#endif
		case SM4_MODE_GCM: rv = sm4_gcm_encrypt_finish(&sm4_ctx.gcm, outbuf, &outlen); break;
		case SM4_MODE_CBC_SM3_HMAC: rv = sm4_cbc_sm3_hmac_encrypt_finish(&sm4_ctx.cbc_sm3_hmac, outbuf, &outlen); break;
		case SM4_MODE_CTR_SM3_HMAC: rv = sm4_ctr_sm3_hmac_encrypt_finish(&sm4_ctx.ctr_sm3_hmac, outbuf, &outlen); break;
		}
		if (rv != 1) {
			error_print();
			goto end;
		}
		if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}

	} else {
		switch (mode) {
#ifdef ENABLE_SM4_ECB
		case SM4_MODE_ECB: rv = sm4_ecb_decrypt_init(&sm4_ctx.ecb, key); break;
#endif
		case SM4_MODE_CBC: rv = sm4_cbc_decrypt_init(&sm4_ctx.cbc, key, iv); break;
#ifdef ENABLE_SM4_CFB
		case SM4_MODE_CFB: rv = sm4_cfb_decrypt_init(&sm4_ctx.cfb, 16, key, iv); break;
#endif
#ifdef ENABLE_SM4_OFB
		case SM4_MODE_OFB: rv = sm4_ofb_encrypt_init(&sm4_ctx.ofb, key, iv); break;
#endif
#ifdef ENABLE_SM4_XTS
		case SM4_MODE_XTS: rv = sm4_xts_decrypt_init(&sm4_ctx.xts, key, iv, xts_data_unit_size); break;
#endif
		case SM4_MODE_GCM: rv = sm4_gcm_decrypt_init(&sm4_ctx.gcm, key, keylen, iv, ivlen, aad, aadlen, GHASH_SIZE); break;
		case SM4_MODE_CBC_SM3_HMAC: rv = sm4_cbc_sm3_hmac_decrypt_init(&sm4_ctx.cbc_sm3_hmac, key, iv, aad, aadlen); break;
		case SM4_MODE_CTR_SM3_HMAC: rv = sm4_ctr_sm3_hmac_decrypt_init(&sm4_ctx.ctr_sm3_hmac, key, iv, aad, aadlen); break;
		}
		if (rv != 1) {
			error_print();
			goto end;
		}

		while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
			switch (mode) {
#ifdef ENABLE_SM4_ECB
			case SM4_MODE_ECB: rv = sm4_ecb_decrypt_update(&sm4_ctx.ecb, inbuf, inlen, outbuf, &outlen); break;
#endif
			case SM4_MODE_CBC: rv = sm4_cbc_decrypt_update(&sm4_ctx.cbc, inbuf, inlen, outbuf, &outlen); break;
#ifdef ENABLE_SM4_CFB
			case SM4_MODE_CFB: rv = sm4_cfb_decrypt_update(&sm4_ctx.cfb, inbuf, inlen, outbuf, &outlen); break;
#endif
#ifdef ENABLE_SM4_OFB
			case SM4_MODE_OFB: rv = sm4_ofb_encrypt_update(&sm4_ctx.ofb, inbuf, inlen, outbuf, &outlen); break;
#endif
#ifdef ENABLE_SM4_XTS
			case SM4_MODE_XTS: rv = sm4_xts_encrypt_update(&sm4_ctx.xts, inbuf, inlen, outbuf, &outlen); break;
#endif
			case SM4_MODE_GCM: rv = sm4_gcm_decrypt_update(&sm4_ctx.gcm, inbuf, inlen, outbuf, &outlen); break;
			case SM4_MODE_CBC_SM3_HMAC: rv = sm4_cbc_sm3_hmac_decrypt_update(&sm4_ctx.cbc_sm3_hmac, inbuf, inlen, outbuf, &outlen); break;
			case SM4_MODE_CTR_SM3_HMAC: rv = sm4_ctr_sm3_hmac_decrypt_update(&sm4_ctx.ctr_sm3_hmac, inbuf, inlen, outbuf, &outlen); break;
			}
			if (rv != 1) {
				error_print();
				goto end;
			}

			if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
				fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
				goto end;
			}
		}

		switch (mode) {
#ifdef ENABLE_SM4_ECB
		case SM4_MODE_ECB: rv = sm4_ecb_decrypt_finish(&sm4_ctx.ecb, outbuf, &outlen); break;
#endif
		case SM4_MODE_CBC: rv = sm4_cbc_decrypt_finish(&sm4_ctx.cbc, outbuf, &outlen); break;
#ifdef ENABLE_SM4_CFB
		case SM4_MODE_CFB: rv = sm4_cfb_decrypt_finish(&sm4_ctx.cfb, outbuf, &outlen); break;
#endif
#ifdef ENABLE_SM4_OFB
		case SM4_MODE_OFB: rv = sm4_ofb_encrypt_finish(&sm4_ctx.ofb, outbuf, &outlen); break;
#endif
#ifdef ENABLE_SM4_XTS
		case SM4_MODE_XTS: rv = sm4_xts_decrypt_finish(&sm4_ctx.xts, outbuf, &outlen); break;
#endif
		case SM4_MODE_GCM: rv = sm4_gcm_decrypt_finish(&sm4_ctx.gcm, outbuf, &outlen); break;
		case SM4_MODE_CBC_SM3_HMAC: rv = sm4_cbc_sm3_hmac_decrypt_finish(&sm4_ctx.cbc_sm3_hmac, outbuf, &outlen); break;
		case SM4_MODE_CTR_SM3_HMAC: rv = sm4_ctr_sm3_hmac_decrypt_finish(&sm4_ctx.ctr_sm3_hmac, outbuf, &outlen); break;
		}
		if (rv != 1) {
			error_print();
			goto end;
		}
		if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	}
	ret = 0;

end:
	gmssl_secure_clear(&sm4_ctx, sizeof(sm4_ctx));
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(iv, sizeof(iv));
	gmssl_secure_clear(inbuf, sizeof(inbuf));
	gmssl_secure_clear(outbuf, sizeof(outbuf));
	if (aad_buf) {
		gmssl_secure_clear(aad_buf, aadlen);
		free(aad_buf);
	}
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
