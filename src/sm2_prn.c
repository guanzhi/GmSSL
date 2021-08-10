/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>


int sm2_key_print(FILE *fp, const SM2_KEY *key, int format, int indent)
{
	format_print(fp, format, indent, "SM2PrivateKey\n");
	indent += 4;
	format_bytes(fp, format, indent, "private_key : ", key->private_key, 32);
	format_print(fp, format, indent, "public_key\n");
	sm2_point_print(fp, &key->public_key, format, indent + 4);
	//format_bytes(fp, format, indent + 4, "x : ", (uint8_t *)&key->public_key, 32);
	//format_bytes(fp, format, indent + 4, "y : ", (uint8_t *)&key->public_key + 32, 32);
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
