/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/sm4.h>
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>


static const char *usage = "{-encrypt|-decrypt} -key hex -iv hex [-pkcs7_padding] [-in file] [-out file]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -encrypt            Encrypt\n"
"    -decrypt            Decrypt\n"
"    -key hex            Symmetric key in HEX format\n"
"    -iv hex             IV in HEX format\n"
"    -pkcs7_padding      Enable PKCS#7 padding\n"
"                        Encrypt input can be any byte length; decrypt input must be a multiple of 16 bytes\n"
"    -in file | stdin    Input data. Without `-pkcs7_padding`, input length must be a multiple of 16 bytes\n"
"    -out file | stdout  Output data\n"
"\n"
"Examples\n"
"\n"
"  KEY=`gmssl rand -outlen 16 -hex`\n"
"  IV=`gmssl rand -outlen 16 -hex`\n"
"  echo -n 0123456789abcdef | gmssl sm4_cbc -encrypt -key $KEY -iv $IV -out sm4_cbc_ciphertext.bin\n"
"  gmssl sm4_cbc -decrypt -key $KEY -iv $IV -in sm4_cbc_ciphertext.bin\n"
"\n"
"  echo -n abc | gmssl sm4_cbc -encrypt -pkcs7_padding -key $KEY -iv $IV -out sm4_cbc_ciphertext.bin\n"
"  gmssl sm4_cbc -decrypt -pkcs7_padding -key $KEY -iv $IV -in sm4_cbc_ciphertext.bin\n"
"\n";

int sm4_cbc_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int enc = -1;
	char *keyhex = NULL;
	char *ivhex = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	int pkcs7_padding = 0;
	uint8_t key[16];
	size_t keylen;
	uint8_t iv[16];
	size_t ivlen;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM4_KEY sm4_key;
	SM4_CBC_CTX ctx;
	uint8_t buf[4096];
	uint8_t outbuf[4096];
	uint8_t block[16];
	size_t block_nbytes = 0;
	size_t inlen;
	size_t outlen;
	size_t nblocks;
	size_t len;
	size_t left;
	size_t inpos;

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
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-encrypt")) {
			if (enc == 0) {
				fprintf(stderr, "gmssl %s: `-encrypt` `-decrypt` should not be used together\n", prog);
				goto end;
			}
			enc = 1;
		} else if (!strcmp(*argv, "-decrypt")) {
			if (enc == 1) {
				fprintf(stderr, "gmssl %s: `-encrypt` `-decrypt` should not be used together\n", prog);
				goto end;
			}
			enc = 0;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyhex = *(++argv);
			if (strlen(keyhex) != sizeof(key) * 2) {
				fprintf(stderr, "gmssl %s: invalid key length\n", prog);
				goto end;
			}
			if (hex_to_bytes(keyhex, strlen(keyhex), key, &keylen) != 1) {
				fprintf(stderr, "gmssl %s: invalid key hex digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-iv")) {
			if (--argc < 1) goto bad;
			ivhex = *(++argv);
			if (strlen(ivhex) != sizeof(iv) * 2) {
				fprintf(stderr, "gmssl %s: invalid IV length\n", prog);
				goto end;
			}
			if (hex_to_bytes(ivhex, strlen(ivhex), iv, &ivlen) != 1) {
				fprintf(stderr, "gmssl %s: invalid IV hex digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-pkcs7_padding")) {
			pkcs7_padding = 1;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "gmssl %s: illegal option `%s`\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "gmssl %s: `%s` option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (enc < 0) {
		fprintf(stderr, "gmssl %s: option -encrypt or -decrypt should be set\n", prog);
		goto end;
	}
	if (!keyhex) {
		fprintf(stderr, "gmssl %s: option `-key` missing\n", prog);
		goto end;
	}
	if (!ivhex) {
		fprintf(stderr, "gmssl %s: option `-iv` missing\n", prog);
		goto end;
	}

	if (pkcs7_padding && enc) {
		if (sm4_cbc_encrypt_init(&ctx, key, iv) != 1) {
			error_print();
			goto end;
		}
	} else if (pkcs7_padding) {
		if (sm4_cbc_decrypt_init(&ctx, key, iv) != 1) {
			error_print();
			goto end;
		}
	} else if (enc) {
		sm4_set_encrypt_key(&sm4_key, key);
	} else {
		sm4_set_decrypt_key(&sm4_key, key);
	}

	while ((inlen = fread(buf, 1, sizeof(buf), infp)) > 0) {

		if (pkcs7_padding && enc) {
			if (sm4_cbc_encrypt_update(&ctx, buf, inlen, buf, &outlen) != 1) {
				error_print();
				goto end;
			}
		} else if (pkcs7_padding) {
			if (sm4_cbc_decrypt_update(&ctx, buf, inlen, buf, &outlen) != 1) {
				error_print();
				goto end;
			}
		} else {
			outlen = 0;
			inpos = 0;

			if (block_nbytes) {
				left = sizeof(block) - block_nbytes;
				if (inlen < left) {
					memcpy(block + block_nbytes, buf, inlen);
					block_nbytes += inlen;
					continue;
				}
				memcpy(block + block_nbytes, buf, left);
				if (enc) {
					sm4_cbc_encrypt_blocks(&sm4_key, iv, block, 1, outbuf);
				} else {
					sm4_cbc_decrypt_blocks(&sm4_key, iv, block, 1, outbuf);
				}
				outlen = sizeof(block);
				inpos = left;
				block_nbytes = 0;
			}

			nblocks = (inlen - inpos) / sizeof(block);
			len = nblocks * sizeof(block);
			if (len) {
				if (enc) {
					sm4_cbc_encrypt_blocks(&sm4_key, iv, buf + inpos, nblocks, outbuf + outlen);
				} else {
					sm4_cbc_decrypt_blocks(&sm4_key, iv, buf + inpos, nblocks, outbuf + outlen);
				}
				outlen += len;
				inpos += len;
			}
			if (inlen > inpos) {
				block_nbytes = inlen - inpos;
				memcpy(block, buf + inpos, block_nbytes);
			}
		}

		if (fwrite(pkcs7_padding ? buf : outbuf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	}
	if (ferror(infp)) {
		fprintf(stderr, "%s: read failure\n", prog);
		goto end;
	}

	if (pkcs7_padding && enc) {
		if (sm4_cbc_encrypt_finish(&ctx, buf, &outlen) != 1) {
			error_print();
			goto end;
		}
	} else if (pkcs7_padding) {
		if (sm4_cbc_decrypt_finish(&ctx, buf, &outlen) != 1) {
			error_print();
			goto end;
		}
	} else {
		if (block_nbytes) {
			fprintf(stderr, "gmssl %s: input length must be multiple of 16 bytes when PKCS#7 padding is not enabled\n", prog);
			goto end;
		}
		outlen = 0;
	}
	if (fwrite(buf, 1, outlen, outfp) != outlen) {
		fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
		goto end;
	}

	ret = 0;

end:
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(iv, sizeof(iv));
	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
	gmssl_secure_clear(&ctx, sizeof(ctx));
	gmssl_secure_clear(outbuf, sizeof(outbuf));
	gmssl_secure_clear(block, sizeof(block));
	gmssl_secure_clear(buf, sizeof(buf));
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
