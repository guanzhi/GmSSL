/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>

// FIXME: 缺乏打印公钥的函数，有时候SM2_KEY中只有公钥，没有私钥
int sm2_key_print(FILE *fp, const SM2_KEY *key, int format, int indent)
{
	format_print(fp, format, indent, "SM2PrivateKey\n");
	indent += 4;
	format_bytes(fp, format, indent, "private_key : ", key->private_key, 32);
	format_print(fp, format, indent, "public_key:\n");
	sm2_point_print(fp, &key->public_key, format, indent + 4);
	return 1;
}

int sm2_point_print(FILE *fp, const SM2_POINT *P, int format, int indent)
{
	format_bytes(fp, format, indent, "x : ", P->x, 32);
	format_bytes(fp, format, indent, "y : ", P->y, 32);
	return 1;
}

int sm2_print_signature(FILE *fp, const uint8_t *der, size_t derlen, int format, int indent)
{
	uint8_t buf[sizeof(SM2_SIGNATURE)] = {0};
	SM2_SIGNATURE *sig = (SM2_SIGNATURE *)buf;
	const uint8_t *p = der;
	int i;

	if (sm2_signature_from_der(sig, &p, &derlen) < 0) {
		fprintf(stderr, "error: %s %d: invalid signature DER encoding\n", __FILE__, __LINE__);
	}
	if (derlen > 0) {
		fprintf(stderr, "error: %s %d: %zu extra bytes at the end of DER\n", __FILE__, __LINE__, derlen);
	}

	format_bytes(fp, format, indent, "r : ", sig->r, 32);
	format_bytes(fp, format, indent, "s : ", sig->s, 32);
	return 1;
}

int sm2_print_ciphertext(FILE *fp, const uint8_t *der, size_t derlen, int format, int indent)
{
	uint8_t buf[512 /* derlen */] = {0}; //FIXME: add -std=c99 to CMakeList.txt
	SM2_CIPHERTEXT *c = (SM2_CIPHERTEXT *)buf;
	const uint8_t *p = der;
	int i;

	if (sm2_ciphertext_from_der(c, &p, &derlen) < 0) {
		fprintf(stderr, "error: %s %d: invalid ciphertext DER encoding\n", __FILE__, __LINE__);
	}
	if (derlen > 0) {
		fprintf(stderr, "error: %s %d: %zu extra bytes at the end of DER\n", __FILE__, __LINE__, derlen);
	}
	sm2_ciphertext_print(fp, c, format, indent);
	return 1;
}

int sm2_ciphertext_print(FILE *fp, const SM2_CIPHERTEXT *c, int format, int indent)
{
	format_bytes(fp, format, indent, "x", c->point.x, 32);
	format_bytes(fp, format, indent, "y", c->point.y, 32);
	format_bytes(fp, format, indent, "hash", c->hash, 32);
	format_bytes(fp, format, indent, "ciphertext", c->ciphertext, c->ciphertext_size);
	return 1;
}
