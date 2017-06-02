/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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
 * ====================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>


#define P_HEX \
	"ab64be0955a39254a6cfe231531c02ebc0cd4c307800c7eb49fabcc179174e04" \
	"00365f7280d166bf67839bba4047bab1212f2966d3045dcfc08d83d57fb7d01b" \
	"6f958e077caeba969057287a8ea75c93660747c68c32af9c874bfd87d1a40c9a" \
	"a709813930f3e7d7d794874146eceb73a14cfc41cfad0007fc30ead26f938349" \
	"a017115a506c49dfb78002ccffaed045b39bc8970756c275d484f60dc7ba609f" \
	"8dfe7142f8dfac81cc53a6bd67e1dcc18f35aad88a94ee40dd90934a282203cb"
#define A_HEX "0"
#define B_HEX "1"
#define X_HEX \
	"6613bde4d70b02a29a1700d2063420e408b0c23c85fdfca2b37df38b872492f1" \
	"91dda03d4c520be9dced93d8678c5a898a9e81ddddb6afc9fa882e808fb48e33" \
	"bd3e08756db0db2b271e82c48139d6b048edffd7736b0aca63f8733c2134ab7e" \
	"0b33f11a0e61b89bd7259b752b24ada949b958f95d2c914b34e29a6ee888acc6" \
	"04ab0d0818fc2ab09546db9eab4a452909ce88298abc644678f8b9ecbee7eb33" \
	"4ffe4c25a8d5fcd7dd4b74d0362033acacd3cd363f22ab2a76605fdc8868654b"
#define Y_HEX \
	"117ff162e1e4a92fc920677f84a2b9ab151f3545f5094f6471d8d02d47bd8b7e" \
	"b09e4ef771710be64809442ee66965406f6a55d317a8dde231d257f5fc2e84bf" \
	"99e3077e9f53cb49e8c6d792437cb1b525ea7e83594b2928e72db64349619fb4" \
	"7392759c9909f7ccd9d7d54b2605969ed59875a39a99e6914404d17d4f5a8ba2" \
	"d7486aa36ee235dcdc4385a292348c4de9373d4cae3fcb07297aef083dc04f10" \
	"d25efb6b60d116d0b95151a3ff96a2eaee556bbac0ad6b6633dfd1c1d5c896e2"
#define N_HEX \
	"ffffffffffffffffffffff000000000000000000000000000000000000000001"
#define H_HEX \
	"ab64be0955a39254a6cfe2dcb7da0c41645fa0d747e3a4a32406fe25d8b8254b" \
	"3876448d322bfa4378d90415feb23ba1e8c9cc086424cf2b4ec2279870cbb334" \
	"5bee74c90caa58c3e33158c07e69e9fe27963fa15966a0efa273d416f717fabf" \
	"b1bbfc12981da60b0c5dee32847f140d975cc7acd434919cd8d12452d543355e" \
	"22ecb2208972f6a9ee5772bd67e1dcc18f35aad88a94ee40dd90934a282203cc"

static EC_GROUP *EC_GROUP_new_hexstrs(int is_prime_field,
	const char *p_hex, const char *a_hex, const char *b_hex,
	const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex)
{
	int ok = 0;
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	EC_POINT *G = NULL;
	point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;
	int flag = 0;

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	if (!BN_hex2bn(&p, p_hex) ||
	    !BN_hex2bn(&a, a_hex) ||
	    !BN_hex2bn(&b, b_hex) ||
	    !BN_hex2bn(&x, x_hex) ||
	    !BN_hex2bn(&y, y_hex) ||
	    !BN_hex2bn(&n, n_hex) ||
	    !BN_hex2bn(&h, h_hex)) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	if (is_prime_field) {
		if (!(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))) {
			ERR_print_errors_fp(stderr);
			goto err;
		}
		if (!(G = EC_POINT_new(group))) {
			ERR_print_errors_fp(stderr);
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GFp(group, G, x, y, ctx)) {
			ERR_print_errors_fp(stderr);
			goto err;
		}
	} else {
		if (!(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))) {
			goto err;
		}
		if (!(G = EC_POINT_new(group))) {
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GF2m(group, G, x, y, ctx)) {
			goto err;
		}
	}

	if (!EC_GROUP_set_generator(group, G, n, h)) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	EC_GROUP_set_asn1_flag(group, flag);
	EC_GROUP_set_point_conversion_form(group, form);

	ok = 1;
err:
	BN_CTX_free(ctx);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(x);
	BN_free(y);
	BN_free(n);
	BN_free(h);
	EC_POINT_free(G);
	if (!ok && group) {
		ERR_print_errors_fp(stderr);
		EC_GROUP_free(group);
		group = NULL;
	}

	return group;
}

EC_GROUP *EC_GROUP_new_sm9s256t1(void)
{
	return EC_GROUP_new_hexstrs(1, P_HEX, A_HEX, B_HEX, X_HEX, Y_HEX, N_HEX, H_HEX);
}

