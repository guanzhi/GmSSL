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
#include <gmssl/ff1.h>
#include <gmssl/hex.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>


#define SM4_FF1_MAX_TWEAK_SIZE	FF1_MAX_TWEAK_SIZE
#define ID_CARD_DIGITS		18
#define ID_CARD_BODY_DIGITS	17


static const char *usage =
	"{-encrypt|-decrypt} -key hex [-tweak hex] [-idcard|-bankcard] [-digits digits]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -encrypt            Encrypt\n"
"    -decrypt            Decrypt\n"
"    -key hex            SM4 key in HEX format\n"
"    -tweak hex          FF1 tweak in HEX format\n"
"    -digits digits      Input digits, default from stdin\n"
"    -idcard             Input is a Chinese resident identity card number\n"
"    -bankcard           Input is a bank card number with Luhn check digit\n"
"\n";

static uint8_t *read_content(FILE *infp, size_t *outlen, const char *prog)
{
	const size_t maxlen = 4096;
	uint8_t *buf = NULL;
	size_t len;

	if (!(buf = malloc(maxlen + 1))) {
		fprintf(stderr, "gmssl %s: malloc failure\n", prog);
		return NULL;
	}
	len = fread(buf, 1, maxlen, infp);
	if (ferror(infp)) {
		fprintf(stderr, "gmssl %s: read failure : %s\n", prog, strerror(errno));
		free(buf);
		return NULL;
	}
	if (!feof(infp)) {
		fprintf(stderr, "gmssl %s: input too long\n", prog);
		free(buf);
		return NULL;
	}
	while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
		len--;
	}
	buf[len] = 0;
	*outlen = len;
	return buf;
}

static int is_digits(const char *s, size_t len)
{
	size_t i;

	if (!s) {
		return 0;
	}
	for (i = 0; i < len; i++) {
		if (s[i] < '0' || s[i] > '9') {
			return 0;
		}
	}
	return 1;
}

static int idcard_check_digit(const char body[ID_CARD_BODY_DIGITS])
{
	static const int weights[ID_CARD_BODY_DIGITS] = {
		7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2,
	};
	static const char check_digits[] = "10X98765432";
	int sum = 0;
	size_t i;

	if (!is_digits(body, ID_CARD_BODY_DIGITS)) {
		return -1;
	}
	for (i = 0; i < ID_CARD_BODY_DIGITS; i++) {
		sum += (body[i] - '0') * weights[i];
	}
	return check_digits[sum % 11];
}

static int idcard_check(const char *s, size_t len)
{
	int ch;
	char last;

	if (!s || len != ID_CARD_DIGITS) {
		return -1;
	}
	ch = idcard_check_digit(s);
	if (ch < 0) {
		return -1;
	}
	last = s[ID_CARD_DIGITS - 1];
	if (last == 'x') {
		last = 'X';
	}
	return last == ch ? 1 : -1;
}

static int luhn_check_digit(const char *body, size_t len)
{
	int sum = 0;
	int double_digit = 1;

	if (!is_digits(body, len)) {
		return -1;
	}
	while (len) {
		int digit = body[--len] - '0';
		if (double_digit) {
			digit *= 2;
			if (digit > 9) {
				digit -= 9;
			}
		}
		sum += digit;
		double_digit = !double_digit;
	}
	return '0' + (10 - sum % 10) % 10;
}

static int bankcard_check(const char *s, size_t len)
{
	int ch;

	if (!s || len < FF1_MIN_DIGITS + 1 || len > FF1_MAX_DIGITS + 1 || !is_digits(s, len)) {
		return -1;
	}
	ch = luhn_check_digit(s, len - 1);
	if (ch < 0) {
		return -1;
	}
	return s[len - 1] == ch ? 1 : -1;
}

int sm4_ff1_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int enc = -1;
	int idcard = 0;
	int bankcard = 0;
	char *keyhex = NULL;
	char *tweakhex = NULL;
	char *digits = NULL;
	uint8_t key[16];
	uint8_t tweak[SM4_FF1_MAX_TWEAK_SIZE];
	size_t keylen = 0;
	size_t tweaklen = 0;
	uint8_t *inbuf = NULL;
	int inbuf_alloc = 0;
	size_t inlen;
	char outbuf[FF1_MAX_DIGITS + 2];
	size_t bodylen;
	BLOCK_CIPHER_KEY block_key;

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
				fprintf(stderr, "gmssl %s: `-encrypt` and `-decrypt` should not be used together\n", prog);
				goto end;
			}
			enc = 1;
		} else if (!strcmp(*argv, "-decrypt")) {
			if (enc == 1) {
				fprintf(stderr, "gmssl %s: `-encrypt` and `-decrypt` should not be used together\n", prog);
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
			if (hex_to_bytes(keyhex, strlen(keyhex), key, &keylen) != 1 || keylen != sizeof(key)) {
				fprintf(stderr, "gmssl %s: invalid key hex digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-tweak")) {
			if (--argc < 1) goto bad;
			tweakhex = *(++argv);
			if (strlen(tweakhex) > sizeof(tweak) * 2) {
				fprintf(stderr, "gmssl %s: invalid tweak length\n", prog);
				goto end;
			}
			if (!strlen(tweakhex)) {
				tweaklen = 0;
			} else if (hex_to_bytes(tweakhex, strlen(tweakhex), tweak, &tweaklen) != 1) {
				fprintf(stderr, "gmssl %s: invalid tweak hex digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-digits")) {
			if (--argc < 1) goto bad;
			if (digits) {
				fprintf(stderr, "gmssl %s: option `-digits` should be set only once\n", prog);
				goto end;
			}
			digits = *(++argv);
		} else if (!strcmp(*argv, "-idcard")) {
			if (bankcard) {
				fprintf(stderr, "gmssl %s: `-idcard` and `-bankcard` should not be used together\n", prog);
				goto end;
			}
			idcard = 1;
		} else if (!strcmp(*argv, "-bankcard")) {
			if (idcard) {
				fprintf(stderr, "gmssl %s: `-idcard` and `-bankcard` should not be used together\n", prog);
				goto end;
			}
			bankcard = 1;
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
	if (tweakhex && tweaklen > FF1_MAX_TWEAK_SIZE) {
		fprintf(stderr, "gmssl %s: invalid tweak length\n", prog);
		goto end;
	}
	if (digits) {
		inbuf = (uint8_t *)digits;
		inlen = strlen(digits);
	} else {
		if (!(inbuf = read_content(stdin, &inlen, prog))) {
			goto end;
		}
		inbuf_alloc = 1;
	}
	if (!inlen) {
		fprintf(stderr, "gmssl %s: empty input\n", prog);
		goto end;
	}

	if (idcard) {
		if (idcard_check((char *)inbuf, inlen) != 1) {
			fprintf(stderr, "gmssl %s: invalid identity card number\n", prog);
			goto end;
		}
		bodylen = ID_CARD_BODY_DIGITS;
	} else if (bankcard) {
		if (bankcard_check((char *)inbuf, inlen) != 1) {
			fprintf(stderr, "gmssl %s: invalid bank card number\n", prog);
			goto end;
		}
		bodylen = inlen - 1;
	} else {
		if (inlen < FF1_MIN_DIGITS || inlen > FF1_MAX_DIGITS || !is_digits((char *)inbuf, inlen)) {
			fprintf(stderr, "gmssl %s: invalid input digits\n", prog);
			goto end;
		}
		bodylen = inlen;
	}

	if (ff1_init(&block_key, BLOCK_CIPHER_sm4(), key) != 1) {
		error_print();
		goto end;
	}
	if (enc) {
		if (ff1_encrypt(&block_key, (char *)inbuf, bodylen, tweak, tweaklen, outbuf) != 1) {
			error_print();
			goto end;
		}
	} else {
		if (ff1_decrypt(&block_key, (char *)inbuf, bodylen, tweak, tweaklen, outbuf) != 1) {
			error_print();
			goto end;
		}
	}

	if (idcard) {
		int ch = idcard_check_digit(outbuf);
		if (ch < 0) {
			error_print();
			goto end;
		}
		outbuf[bodylen] = (char)ch;
		outbuf[bodylen + 1] = '\0';
		bodylen++;
	} else if (bankcard) {
		int ch = luhn_check_digit(outbuf, bodylen);
		if (ch < 0) {
			error_print();
			goto end;
		}
		outbuf[bodylen] = (char)ch;
		outbuf[bodylen + 1] = '\0';
		bodylen++;
	}

	if (fwrite(outbuf, 1, bodylen, stdout) != bodylen) {
		fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
		goto end;
	}

	ret = 0;

end:
	if (inbuf_alloc) free(inbuf);
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(tweak, sizeof(tweak));
	gmssl_secure_clear(&block_key, sizeof(block_key));
	return ret;
}
