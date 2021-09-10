/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <gmssl/error.h>

int OPENSSL_hexchar2int(unsigned char c)
{
    switch (c) {
    case '0':
        return 0;
    case '1':
        return 1;
    case '2':
        return 2;
    case '3':
        return 3;
    case '4':
          return 4;
    case '5':
          return 5;
    case '6':
          return 6;
    case '7':
          return 7;
    case '8':
          return 8;
    case '9':
          return 9;
    case 'a':
    case 'A':
          return 0x0A;
    case 'b': case 'B':
          return 0x0B;
    case 'c': case 'C':
          return 0x0C;
    case 'd': case 'D':
          return 0x0D;
    case 'e': case 'E':
          return 0x0E;
    case 'f': case 'F':
          return 0x0F;
    }
    return -1;
}

unsigned char *OPENSSL_hexstr2buf(const char *str, size_t *len)
{
    unsigned char *hexbuf, *q;
    unsigned char ch, cl;
    int chi, cli;
    const unsigned char *p;
    size_t s;

    s = strlen(str);
    if ((hexbuf = malloc(s >> 1)) == NULL) {
        return NULL;
    }
    for (p = (const unsigned char *)str, q = hexbuf; *p; ) {
        ch = *p++;
        if (ch == ':')
            continue;
        cl = *p++;
        if (!cl) {
            //CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, CRYPTO_R_ODD_NUMBER_OF_DIGITS);
            free(hexbuf);
            return NULL;
        }
        cli = OPENSSL_hexchar2int(cl);
        chi = OPENSSL_hexchar2int(ch);
        if (cli < 0 || chi < 0) {
            free(hexbuf);
            //CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, CRYPTO_R_ILLEGAL_HEX_DIGIT);
            return NULL;
        }
        *q++ = (unsigned char)((chi << 4) | cli);
    }

    if (len)
        *len = q - hexbuf;
    return hexbuf;
}


static int hexchar2int(char c)
{
	if      ('0' <= c && c <= '9') return c - '0';
	else if ('a' <= c && c <= 'f') return c - 'a' + 10;
	else if ('A' <= c && c <= 'F') return c - 'A' + 10;
	else return -1;
}

int hex2bin(const char *in, size_t inlen, uint8_t *out)
{
	int c;
	if (inlen % 2) {
		error_print_msg("hex %s len = %zu\n", in, inlen);
		return -1;
	}

	while (inlen) {
		if ((c = hexchar2int(*in++)) < 0) {
			error_print_msg("%d", 5);
			return -1;
		}
		*out = (uint8_t)c << 4;
		if ((c = hexchar2int(*in++)) < 0) {
			error_print();
			return -1;
		}
		*out |= (uint8_t)c;
		inlen -= 2;
		out++;
	}
	return 1;
}

int hex_to_bytes(const char *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	*outlen = inlen/2;
	return hex2bin(in, inlen, out);
}


void memxor(void *r, const void *a, size_t len)
{
	uint8_t *pr = r;
	const uint8_t *pa = a;
	size_t i;
	for (i = 0; i < len; i++) {
		pr[i] ^= pa[i];
	}

}


void gmssl_memxor(void *r, const void *a, const void *b, size_t len)
{
	uint8_t *pr = r;
	const uint8_t *pa = a;
	const uint8_t *pb = b;
	size_t i;
	for (i = 0; i < len; i++) {
		pr[i] = pa[i] ^ pb[i];
	}
}

int gmssl_memcmp(const void *s1, const void *s2, size_t n)
{
	return memcmp(s1, s2, n);
}






