/* ====================================================================
 * Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.
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
#include <string.h>
#include <stdlib.h>

#include "../e_os.h"

#ifdef OPENSSL_NO_SM2
int main(int argc, char **argv)
{
	printf("No SM2 support\n");
	return 0;
}
#else
# include <openssl/bn.h>
# include <openssl/err.h>

char *p_hex =
	"fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff";

char *Ta[16] = {
	"3e95aa4bda8cfe30a4fedd12dbc9c717ea3ed847de1eb230b56fbb76dc7217ba",
	"0332a233a6f193ba8fdc36aa331e3e4ff6db5b431d6f8ecf528f5ca77ec2cafc",
	"de14982f3a95b35bde14f8e26e779f1823b52b524614492ed9746ebba60bba60",
	"d935ae35237a8a00e6dcc0e7f9d8f8b178c60b90aa4a9edba14e29187deb303c",
	"b72d57518c824a49349f61e42c6ac8ceae7d2cafd6ccbc661b3dfda7dba19e2c",
	"d804f88a76c834fef9aed537ae08abbdf9ad01d29bfb93ae0248dcd48f10ff03",
	"6f20acfd42570d70f8fc0be3a3200fec0df9f0f9186f49c353e02cd711144f27",
	"bcf5d0290e9cfe328f6da2179a5cd15b5e92818e4fd5695c8e74c43d9cb6a701",
	"5d1c0e13bbd739016ff7d539ed29dfdef4ee51a5646a23e7d61e0f74953be23a",
	"e429b89f63dc08ad37ba0157b7668043972e83c62677cb8374c365a3ebcfad98",
	"3656d93ded9d7bd0f36a1a6f463035a2acff5b99aa2025c5c40aa942b3609f4e",
	"b4470ef698d6e3f805b9d6df1b39564fcbd481e4b5b979a9a2c19dc44301ff34",
	"f8727645f651f9583f8045b8d03d870a084ff3c2dc0b512774cbe6ef2fd7a042",
	"0ac73c2a55cc2ab2b7366f9e3e831be2173ed8aa317c082d21b43814c5bbb55b",
	"2b3d206349d856869ee04879520c45849bc839a23f6bf31ec26a942f3714fe70",
	"8bdc15845f151a371261983176cbb4643b63820ef75bcc159276e57861a87d9f"
};

char *Tb[16] = {
	"3ab79dae0977801554ba17ca3011320dde32753be2bce5779963f89a9713ba30",
	"5781be359f5bc50f519e62121212f2ea8b719088084f999a42fcde2cbfa15d25",
	"2c091793914df5c1771c11c0febadea11e6e826b8076c0d77b15f1e5381d5e80",
	"42feb510f9851db5b73df5a13191553ee19c3539aeb5d009ff904d248eb2da7c",
	"e278fb3543f283f353f9343e396cc9f68177d222c094d4bab6428d01df9c29e0",
	"de64bf43a3f03b7c9f952047180da55bba7050352d9b3934d32e5030731bab73",
	"f226021bdb0c3bb459a4d9fd04adb22c7e6e690ec0f90f18be60cdee75193ce9",
	"2a05f135b1fc1a68f8464a59de1a80abeac464d9b2d91b6dc5745f83dd1faa66",
	"fe60739515a0849bb421977d75ba568e9d7a1e8088b63835152c315123fb76b1",
	"e64af9f44c16ab4de008cf6c238d01ca9fa07d8f6f7edbc0de0db6e2b06ec476",
	"0264b26614dc8c5de82b597f306e8004022215a5f6e6f88095f457886fb655ff",
	"0855b2084bac721af536aa9fb03eb242a2d81f00eca6c9fc15960deaec5ebc27",
	"e4b0e4911c8d8d8dbc384e08a8ad14580ca3edd85b235587d8cc730831736a50",
	"e3d76ccf7077b8ac0c833b1690cf5e75c98a4a4afa261a9de1361f22b5c1dab0",
	"b200f0cc46441d1f63b76a21c7ca3ccf1cb5098328346442ced152dfb133ad6e",
	"e54b8a3fbf8111a8b7034234db0d4f33877795f8e835e88e924e3fab0b84de76"
};

char *Taa[16] = {
	"fefe3ef6b44fe582cba8a7129342ef77cd4b5ba521c7189aa5a8e112297d5d90",
	"b3cb5f26b04865c26fe52442f4c1ebb656e1760a5ea3d62cb3e63784d371e95f",
	"8a1f710e0809ec96aa9578dc192179a91a75d717307620de8009bdd58a76b640",
	"c8622749944ee9c815afcc9f4c1c531ca3631cb88e30a99492b6cb62dce39e1d",
	"1df74baa8735762b2454bc6b294faae59abd34950298e4a81235a859d46b71b4",
	"f275f396ab1f5f94ffebf7122d4c565386a82a2c4e7b54d65335a8f597c2a761",
	"41f67881b2363cace465445a266e121d805e2c54ddf0c3e30a4d27a3dbf4a4e0",
	"bf59edd5a40c7be98ce7e8a39fbaee406e71954e3dede913137a24f9146bac11",
	"d9fe01c962f5258235bc68c2d156beeea2943d3fbe339b67b3d37a584ad441d2",
	"a1f96949368b19f322d3b3b4bf738df4f82abd606ba17fb2e98ef08603fe39db",
	"b60591f7ba01ee5ae0e66230af82b95f5baeed68710b7e1fd6da2f5b92dfc9b6",
	"245428a6ae6a23ebd5392d6057b0da46aa1d687f671641b85e1b9d6c76d66837",
	"e9ed1864d00962be7004bbe3a827ef38c71c5e5a89cef53a8af502040f45985e",
	"413362934bbcfd5f129d3667977fb8abbf197d812b365de1b54c1689439c219c",
	"6ce43fd6f149249ddd5978d84e5f9f482f24d73a4f635004756b9bcbdbbb333d",
	"5a10fbf4ca73edd7d241b08fc8f91097f0be0c468568b000e529d5635ecbf638"};

char *Tab[16] = {
	"83a06323ff1c7a0a0dece07e002fc51c27d7ea3d46ca8cb55d11c520b161dfae",
	"c7daea5a75a7b89efb729495c0e8e732793ceeca3fc4aad63078e035bc4d5228",
	"a9a40cb6f64e63a18cf3d562ee2af60803643b20d871e76cc1efbad9a6a2f1b2",
	"6e1099c1997a5be42e41135377f7cf1d80a3fdd46dfec4c13e6949b6b7508851",
	"ebc48a2218775787b6aaf3512218696d149fd7bc28d41490a8c34145aefb5cac",
	"43e4de497fc218ed2743ac3196a7249b103590a270a1ed1a3a8e1ef0e4250210",
	"52b26b8d9dfc72fe749d13904a0ca1c1bc5702fc63f7918a61397fa21ecc4c36",
	"93fb9109741df1a92169282635522c713415598975d4598df631501698cf286c",
	"23ba2c47496673c49ade25f59a62e1ce33fc57951d7aacd7c9c2c6a168b6f04b",
	"9f63cb1fd968a7aaa7785f6ff31fb96f23e3db9745a3abb1c5ef7cb02ceaa386",
	"d33f1ddcef824e8ca9bf8faa7f1cdc96af34e04215eea2ab7c631b4f6a8fb2de",
	"529d341140ea9fe004ca501e882986ca7ce172903a3fee8c2a1b079f16e6a836",
	"bd3c2fb5a7cb62141d5a9d1cc877cd5e8bdbdc59c7c942f1ad90125525791ad0",
	"741788ad3326a9ab890952c7ea2be6bab10a6beb5390561cab87b9d9c8ecb893",
	"8cb7568e7512139244437066d6d9236d2d2fb9d39930aa84f1363730175ecf34",
	"6b818ebe5753e16325e6ddbe33de2a1c3da04793b19f2999611962278af4d13c"};


int main(int argc, char **argv)
{
	int err = 0;
	BN_CTX *ctx = NULL;
	BIGNUM *p;
	BIGNUM *a;
	BIGNUM *b;
	BIGNUM *aa;
	BIGNUM *ab;
	BIGNUM *raa;
	BIGNUM *rab;
	int i;

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	BN_CTX_start(ctx);

	p = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	aa = BN_CTX_get(ctx);
	ab = BN_CTX_get(ctx);
	raa = BN_CTX_get(ctx);
	rab = BN_CTX_get(ctx);
	if (!a || !b || !aa || !ab || !raa || !rab) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* check BN_get0_sm2_prime_256() */
	if (!BN_hex2bn(&p, p_hex)) {
		ERR_print_errors_fp(stderr);
		err = 1;
		goto end;
	}
	if (BN_ucmp(p, BN_get0_sm2_prime_256())) {
		printf("error on sm2 prime value\n");
		err - 1;
		goto end;
	}

	/* check BN_sm2_mod_256() */
	for (i = 0; i < sizeof(Ta)/sizeof(Ta[0]); i++) {
		if (!BN_hex2bn(&a, Ta[i])
			|| !BN_hex2bn(&b, Tb[i])
			|| !BN_hex2bn(&aa, Taa[i])
			|| !BN_hex2bn(&ab, Tab[i])
			|| !BN_sqr(raa, a, ctx)
			|| !BN_sm2_mod_256(raa, raa, p, ctx)
			|| !BN_mul(rab, a, b, ctx)
			|| !BN_sm2_mod_256(rab, rab, p, ctx)) {
			ERR_print_errors_fp(stderr);
			err = 1;
			goto end;
		}

		if (BN_ucmp(raa, aa)) {
			printf("error reducing square with sm2 prime on test %d\n", i+1);
			err++;
		} else {
			print ("test %d square mod sm2 prime ok\n", i+1);
		}
		if (BN_ucmp(rab, ab)) {
			printf("error reducing product with sm2 prime on test %d\n", i);
			err++;
		} else {
			print ("test %d square mod sm2 prime ok\n", i+1);
		}
	}

end:
	if (ctx) {
		BN_CTX_end(ctx);
	}
	BN_CTX_free(ctx);
	return 0;
}
#endif
