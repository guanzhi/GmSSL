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
