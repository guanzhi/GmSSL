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


static const char *usage = "{-encrypt|-decrypt} -key hex -iv hex [-aad str| -aad_hex hex] [-taglen num] [-in file] [-out file]";

static const char *options =
"Options\n"
"\n"
"    -encrypt            Encrypt\n"
"    -decrypt            Decrypt\n"
"    -key hex            Symmetric key in HEX format\n"
"    -iv hex             IV in HEX format, 7 to 13 bytes\n"
"    -aad str            Authenticated-only message\n"
"    -aad_hex hex        Authenticated-only data in HEX format\n"
"    -taglen num         MAC tag length, 4 to 16 bytes\n"
"    -in file | stdin    Input data\n"
"    -out file | stdout  Output data\n"
"\n"
"Examples\n"
"\n"
"  $ TEXT=`gmssl rand -outlen 20 -hex`\n"
"  $ KEY=`gmssl rand -outlen 16 -hex`\n"
"  $ IV=`gmssl rand -outlen 12 -hex`\n"
"  $ AAD=\"The AAD Data\"\n"
"  $ echo -n $TEXT | gmssl sm4_ccm -encrypt -key $KEY -iv $IV -aad $AAD -out sm4_ccm_ciphertext.bin\n"
"  $ gmssl sm4_ccm -decrypt -key $KEY -iv $IV -aad $AAD -in sm4_ccm_ciphertext.bin\n"
"\n";

static uint8_t *read_content(FILE *infp, size_t *outlen, const char *prog)
{
	const size_t INITIAL_BUFFER_SIZE = 4096;
	const size_t MAX_BUFFER_SIZE = 512 * 1024 * 1024;
	uint8_t *buffer = NULL;
	size_t buffer_size = INITIAL_BUFFER_SIZE;
	size_t total_read = 0;

	if (!(buffer = (uint8_t *)malloc(INITIAL_BUFFER_SIZE))) {
		fprintf(stderr, "gmssl %s: malloc failure\n", prog);
		return NULL;
	}

	while (1) {
		size_t bytes_read;

		if (total_read == buffer_size) {
			uint8_t *new_buffer;

			if (buffer_size >= MAX_BUFFER_SIZE) {
				fprintf(stderr, "gmssl %s: input too long, should be less than %zu\n", prog, MAX_BUFFER_SIZE);
				free(buffer);
				return NULL;
			}
			buffer_size = buffer_size * 2;
			if (buffer_size > MAX_BUFFER_SIZE) {
				buffer_size = MAX_BUFFER_SIZE;
			}

			if (!(new_buffer = (uint8_t *)realloc(buffer, buffer_size))) {
				fprintf(stderr, "gmssl %s: realloc failure\n", prog);
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
			fprintf(stderr, "gmssl %s: fread error\n", prog);
			perror("error reading input");
			free(buffer);
			return NULL;
		}
	}

	*outlen = total_read;

	return buffer;
}

int sm4_ccm_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int enc = -1;
	char *keyhex = NULL;
	char *ivhex = NULL;
	uint8_t *aad = NULL;
	uint8_t *aad_buf = NULL;
	size_t aadlen = 0;
	int taglen = SM4_CCM_DEFAULT_TAG_SIZE;
	char *infile = NULL;
	char *outfile = NULL;
	uint8_t key[16];
	size_t keylen;
	uint8_t iv[SM4_CCM_MAX_IV_SIZE];
	size_t ivlen;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM4_KEY sm4_key;
	uint8_t *inbuf = NULL;
	size_t inlen;
	uint8_t *outbuf = NULL;
	size_t outlen;
	uint8_t *tag;

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
			if (strlen(ivhex) > sizeof(iv) * 2) {
				fprintf(stderr, "gmssl %s: invalid IV length\n", prog);
				goto end;
			}
			if (hex_to_bytes(ivhex, strlen(ivhex), iv, &ivlen) != 1) {
				fprintf(stderr, "gmssl %s: invalid IV hex digits\n", prog);
				goto end;
			}
			if (ivlen < SM4_CCM_MIN_IV_SIZE || ivlen > SM4_CCM_MAX_IV_SIZE) {
				fprintf(stderr, "gmssl %s invalid IV length\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-aad")) {
			if (--argc < 1) goto bad;
			if (aad) {
				fprintf(stderr, "gmssl %s: `-aad` or `aad_hex` has been specified\n", prog);
				goto bad;
			}
			aad = (uint8_t *)(*(++argv));
			aadlen = strlen((char *)aad);
		} else if (!strcmp(*argv, "-aad_hex")) {
			if (--argc < 1) goto bad;
			if (aad) {
				fprintf(stderr, "gmssl %s: `-aad` or `aad_hex` has been specified\n", prog);
				goto bad;
			}
			aad = (uint8_t *)(*(++argv));
			if (!(aad_buf = malloc(strlen((char *)aad)/2 + 1))) {
				fprintf(stderr, "gmssl %s: malloc failure\n", prog);
				goto end;
			}
			if (hex_to_bytes((char *)aad, strlen((char *)aad), aad_buf, &aadlen) != 1) {
				fprintf(stderr, "gmssl %s: `-aad_hex` invalid HEX format argument\n", prog);
				goto end;
			}
			aad = aad_buf;
		} else if (!strcmp(*argv, "-taglen")) {
			if (--argc < 1) goto bad;
			taglen = atoi(*(++argv));
			if (taglen < SM4_CCM_MIN_TAG_SIZE || taglen > SM4_CCM_MAX_TAG_SIZE) {
				fprintf(stderr, "%s: `-taglen` invalid integer argument\n", prog);
				goto end;
			}
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

	sm4_set_encrypt_key(&sm4_key, key);

	if (!(inbuf = read_content(infp, &inlen, prog))) {
		goto end;
	}

	if (enc) {
		outlen = inlen + taglen;
		if (!(outbuf = (uint8_t *)malloc(outlen))) {
			fprintf(stderr, "gmssl %s: malloc failure\n", prog);
			goto end;
		}
		tag = outbuf + inlen;
		if (sm4_ccm_encrypt(&sm4_key, iv, ivlen, aad, aadlen, inbuf, inlen, outbuf, taglen, tag) != 1) {
			error_print();
			goto end;
		}

	} else {
		if (inlen < (size_t)taglen) {
			fprintf(stderr, "gmssl %s: input length (%zu bytes) shorter than tag length (%d bytes)\n",
				prog, inlen, taglen);
			goto end;
		}
		outlen = inlen - taglen;
		tag = inbuf + inlen - taglen;
		if (!(outbuf = (uint8_t *)malloc(outlen))) {
			fprintf(stderr, "gmssl %s: malloc failure\n", prog);
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

	ret = 0;

end:
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(iv, sizeof(iv));
	gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	if (inbuf) free(inbuf);
	if (outbuf) free(outbuf);
	return ret;
}
