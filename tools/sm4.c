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
#include <gmssl/hex.h>
#include <gmssl/aead.h>
#include <gmssl/error.h>


#define SM4_MODE_CBC 1
#define SM4_MODE_CTR 2
#define SM4_MODE_GCM 3
#define SM4_MODE_CBC_SM3_HMAC 4
#define SM4_MODE_CTR_SM3_HMAC 5


static const char *usage = "(-cbc|-ctr|-gcm|-cbc_sm3_hmac|-ctr_sm3_hmac) {-encrypt|-decrypt} -key hex -iv hex [-aad str| -aad_hex hex] [-in file] [-out file]";

static const char *options =
"Options\n"
"\n"
"  Modes\n"
"\n"
"    -cbc                CBC mode with padding, need 16-byte key and 16-byte iv\n"
"    -ctr                CTR mode, need 16-byte key and 16-byte iv\n"
"    -gcm                GCM mode, need 16-byte key and any iv length\n"
"    -cbc_sm3_hmac       CBC mode with padding and HMAC-SM3 (encrypt-then-mac), need 48-byte key and 16-byte iv\n"
"    -ctr_sm3_hmac       CTR mode with HMAC-SM3 (entrypt-then-mac), need 48-byte key and 16-byte iv\n"
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
	size_t keylen = sizeof(key);
	size_t ivlen = sizeof(iv);
	FILE *infp = stdin;
	FILE *outfp = stdout;
	int mode = 0;
	int enc = -1;
	int rv;
	union {
		SM4_CBC_CTX cbc;
		SM4_CTR_CTX ctr;
		SM4_CBC_SM3_HMAC_CTX cbc_sm3_hmac;
		SM4_CTR_SM3_HMAC_CTX ctr_sm3_hmac;
		SM4_GCM_CTX gcm;
	} sm4_ctx;
	uint8_t inbuf[4096];
	size_t inlen;
	uint8_t outbuf[4196];
	size_t outlen;

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
			enc = 1;
		} else if (!strcmp(*argv, "-decrypt")) {
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
	if (!ivhex) {
		fprintf(stderr, "%s: option `-iv` missing\n", prog);
		goto end;
	}

	switch (mode) {
	case SM4_MODE_CTR:
	case SM4_MODE_CBC:
	case SM4_MODE_GCM:
		if (keylen != 16) {
			fprintf(stderr, "%s: invalid key length, should be 32 hex digits\n", prog);
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

	switch (mode) {
	case SM4_MODE_CTR:
	case SM4_MODE_CBC:
	case SM4_MODE_CBC_SM3_HMAC:
	case SM4_MODE_CTR_SM3_HMAC:
		if (ivlen != 16) {
			fprintf(stderr, "%s: invalid IV length, should be 32 hex digits\n", prog);
			goto end;
		}
		break;
	}

	switch (mode) {
	case SM4_MODE_CBC:
	case SM4_MODE_CTR:
		if (aad) {
			fprintf(stderr, "%s: specified mode does not support `-aad` nor `-aad_hex`\n", prog);
			goto end;
		}
		break;
	}

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

	if (enc) {
		switch (mode) {
		case SM4_MODE_CBC: rv = sm4_cbc_encrypt_init(&sm4_ctx.cbc, key, iv); break;
		case SM4_MODE_GCM: rv = sm4_gcm_encrypt_init(&sm4_ctx.gcm, key, keylen, iv, ivlen, aad, aadlen, GHASH_SIZE); break;
		case SM4_MODE_CBC_SM3_HMAC: rv = sm4_cbc_sm3_hmac_encrypt_init(&sm4_ctx.cbc_sm3_hmac, key, keylen, iv, ivlen, aad, aadlen); break;
		case SM4_MODE_CTR_SM3_HMAC: rv = sm4_ctr_sm3_hmac_encrypt_init(&sm4_ctx.ctr_sm3_hmac, key, keylen, iv, ivlen, aad, aadlen); break;
		}
		if (rv != 1) {
			error_print();
			goto end;
		}

		while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
			switch (mode) {
			case SM4_MODE_CBC: rv = sm4_cbc_encrypt_update(&sm4_ctx.cbc, inbuf, inlen, outbuf, &outlen); break;
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
		case SM4_MODE_CBC: rv = sm4_cbc_encrypt_finish(&sm4_ctx.cbc, outbuf, &outlen); break;
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
		case SM4_MODE_CBC: rv = sm4_cbc_decrypt_init(&sm4_ctx.cbc, key, iv); break;
		case SM4_MODE_GCM: rv = sm4_gcm_decrypt_init(&sm4_ctx.gcm, key, keylen, iv, ivlen, aad, aadlen, GHASH_SIZE); break;
		case SM4_MODE_CBC_SM3_HMAC: rv = sm4_cbc_sm3_hmac_decrypt_init(&sm4_ctx.cbc_sm3_hmac, key, keylen, iv, ivlen, aad, aadlen); break;
		case SM4_MODE_CTR_SM3_HMAC: rv = sm4_ctr_sm3_hmac_decrypt_init(&sm4_ctx.ctr_sm3_hmac, key, keylen, iv, ivlen, aad, aadlen); break;
		}
		if (rv != 1) {
			error_print();
			goto end;
		}

		while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
			switch (mode) {
			case SM4_MODE_CBC: rv = sm4_cbc_decrypt_update(&sm4_ctx.cbc, inbuf, inlen, outbuf, &outlen); break;
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
		case SM4_MODE_CBC: rv = sm4_cbc_decrypt_finish(&sm4_ctx.cbc, outbuf, &outlen); break;
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
