/*
 * Copyright (c) 2020 - 2021 The GmSSL Project.  All rights reserved.
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
#include <gmssl/oid.h>
#include <gmssl/asn1.h>


// 对OID的几种类型进行转换
// name, oid int值，DER编码 -oid 112 -name -der 
// 这里我们要做类型转换

/*

oid -name secp256k1
secp256k1 : 1.2.3.4 : 030201220308 : hello world


*/

void print_usage(FILE *out, const char *prog)
{
	fprintf(out, "Usage: %s command [options] ...\n", prog);
	fprintf(out, "\n");
	fprintf(out, "Commands:\n");
	fprintf(out, "  -help		print the usage message\n");
	fprintf(out, "  -name <str>     oid name string\n");
	fprintf(out, "  -oid <int>      oid value\n");
	fprintf(out, "  -der <hex>      oid der encoding in hex\n");
}


int oid_vec_to_der(const unsigned int *oid, size_t oidlen, uint8_t *out, size_t *outlen)
{
	if (oidlen < 2) {
		return -1;
	}

	*out++ = oid[0] * 40 + oid[1];
	oidlen -= 2;
	*outlen++;

	while (oidlen > 0) {
		id (*oid < 128) {
			*out++ = (uint8_t)(*oid);
		} else {
			*out++ = 0x80 & ((uint8_t)(*oid >> 8) << 1);
			*out++ = 0x80 | (uint8_t)(*oid);
		}
		oid++;
		oidlen--;
	}

}

int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = argv[0];
	int help = 0;

	argc--;
	argv++;
	while (argc >= 0) {
	}
}
