/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>
#include <gmssl/rand.h>


static int sm9_bn_equ_hex(const sm9_bn_t a, const char *hex)
{
	sm9_bn_t b;
	sm9_bn_from_hex(b, hex);
	return (sm9_bn_cmp(a, b) == 0);
}


#define hex_iv 		"123456789abcdef00fedcba987654321123456789abcdef00fedcba987654321"
#define hex_fp_add 	"114efe24536598809df494ff7657484edff1812d51c3955b7d869149aa123d31"
#define hex_fp_sub 	"43cee97c9abed9be3efe7ffffc9d30abe1d643b9b27ea351460aabb2239d3fd4"
#define hex_fp_nsub 	"7271168367e4cd3397052b4ff8f19699401c4f9167fc4b8a9f64ef75bfb405a9"
#define hex_fp_dbl 	"551de7a0ee24723edcf314ff72f478fac1c7c4e7044238acc3913cfbcdaf7d05"
#define hex_fp_tri 	"248cdb7163e4d7e5606ac9d731a751d591b25db4f925dd9532a20de5c2de98c9"
#define hex_fp_div2 	"9df779e83d83d9c517bf85bbd4e833b289e7dfb214ecc1501cf8039cdde8d35f"
#define hex_fp_neg 	"30910c2f8a3f9a597c884b28414d2725301567320b1c5b1790ef2f160ad0e43c"
#define hex_fp_mul 	"9e4d19bb5d94a47352e6f53f4116b2a71b16a1113dc789b26528ee19f46b72e0"
#define hex_fp_sqr 	"46dc2a5b8853234b341d9c57f9c4ca5709e95bbfef25356812e884e4f38cd0d6"
#define hex_fp_pow 	"5679a8f0a46ada5b9d48008cde0b8b7a233f882c08afe8f08a36a20ac845bb1a"
#define hex_fp_inv 	"7d404b0027a93e3fa8f8bc7ee367a96814c42a3b69feb1845093406948a34753"

int test_sm9_fp() {
	const SM9_TWIST_POINT _P2 = {
		{{0xAF82D65B, 0xF9B7213B, 0xD19C17AB, 0xEE265948, 0xD34EC120, 0xD2AAB97F, 0x92130B08, 0x37227552},
		 {0xD8806141, 0x54806C11, 0x0F5E93C4, 0xF1DD2C19, 0xB441A01F, 0x597B6027, 0x78640C98, 0x85AEF3D0}},
		{{0xC999A7C7, 0x6215BBA5, 0xA71A0811, 0x47EFBA98, 0x3D278FF2, 0x5F317015, 0x19BE3DA6, 0xA7CF28D5},
		 {0x84EBEB96, 0x856DC76B, 0xA347C8BD, 0x0736A96F, 0x2CBEE6ED, 0x66BA0D26, 0x2E845C12, 0x17509B09}},
		{{1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0}},
	};
	const SM9_TWIST_POINT *P2 = &_P2;
	const SM9_TWIST_POINT _Ppubs = {
		{{0x96EA5E32, 0x8F14D656, 0x386A92DD, 0x414D2177, 0x24A3B573, 0x6CE843ED, 0x152D1F78, 0x29DBA116},
		 {0x1B94C408, 0x0AB1B679, 0x5E392CFB, 0x1CE0711C, 0x41B56501, 0xE48AFF4B, 0x3084F733, 0x9F64080B}},
		{{0xB4E3216D, 0x0E75C05F, 0x5CDFF073, 0x1006E85F, 0xB7A46F74, 0x1A7CE027, 0xDDA532DA, 0x41E00A53},
	         {0xD0EF1C25, 0xE89E1408, 0x1A77F335, 0xAD3E2FDB, 0x47E3A0CB, 0xB57329F4, 0xABEA0112, 0x69850938}},
		{{1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0}},
	};
	const SM9_TWIST_POINT *Ppubs = &_Ppubs;
	sm9_fp_t x;
	sm9_fp_t y;
	sm9_fp_t r;
	int j = 1;

	sm9_bn_copy(x, P2->X[1]);
	sm9_bn_copy(y, Ppubs->Y[0]);

	sm9_fp_t iv = {0x87654321, 0x0fedcba9, 0x9abcdef0, 0x12345678, 0x87654321, 0x0fedcba9, 0x9abcdef0, 0x12345678};
	sm9_bn_from_hex(r, hex_iv); if (sm9_bn_cmp(r, iv) != 0) goto err; ++j;

	sm9_fp_add(r, x, y); if (!sm9_bn_equ_hex(r, hex_fp_add)) goto err; ++j;
	sm9_fp_sub(r, x, y); if (!sm9_bn_equ_hex(r, hex_fp_sub)) goto err; ++j;
	sm9_fp_sub(r, y, x); if (!sm9_bn_equ_hex(r, hex_fp_nsub)) goto err; ++j;
	sm9_fp_dbl(r, x);    if (!sm9_bn_equ_hex(r, hex_fp_dbl)) goto err; ++j;
	sm9_fp_tri(r, x);    if (!sm9_bn_equ_hex(r, hex_fp_tri)) goto err; ++j;
	sm9_fp_div2(r, x);   if (!sm9_bn_equ_hex(r, hex_fp_div2)) goto err; ++j;
	sm9_fp_neg(r, x);    if (!sm9_bn_equ_hex(r, hex_fp_neg)) goto err; ++j;
	sm9_fp_mul(r, x, y); if (!sm9_bn_equ_hex(r, hex_fp_mul)) goto err; ++j;
	sm9_fp_sqr(r, x);    if (!sm9_bn_equ_hex(r, hex_fp_sqr)) goto err; ++j;
	sm9_fp_pow(r, x, y); if (!sm9_bn_equ_hex(r, hex_fp_pow)) goto err; ++j;
	sm9_fp_inv(r, x);    if (!sm9_bn_equ_hex(r, hex_fp_inv)) goto err; ++j;

	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s() test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

#define hex_x		"483f336f119053cba8c0e738cabc2bfdbf047caf7e1aaa92526fa48041ceea2b"
#define hex_y		"3220b45276e3692a387faa7bf3cd46e390608f2f4298cce467bf2b7fda091edb"
#define hex_fn_add 	"7a5fe7c18873bcf5e14091b4be8972e14f650bdec0b37776ba2ed0001bd80906"
#define hex_fn_sub 	"161e7f1c9aaceaa170413cbcd6eee51a2ea3ed803b81ddadeab0790067c5cb50"
#define hex_fn_nsub 	"a02180e367f6bc5065c26e931e9fe22a1b4ea5cadd68ae40fabe689c6ed903d5"
#define hex_fn_mul 	"25c528484b65755b1ff57b47b77f2b32e20467be1dde566ede4264b2e092d223"
#define hex_fn_pow 	"445cb9b76f27e9d03a2c30fbabb59b0ea6d7b06259b0c8a1b30f21b9b274a055"
#define hex_fn_inv 	"3e3e849c2144c3596d9c79cb1f8ee7c60828787e298b06cc341a9a165191bc5e"

int test_sm9_fn() {
	sm9_fn_t x;
	sm9_fn_t y;
	sm9_fn_t r;
	int j = 1;

	sm9_bn_from_hex(x, hex_x);
	sm9_bn_from_hex(y, hex_y);

	sm9_fn_t iv = {0, 0, 0, 0, 0, 0, 0, 0}; if (!sm9_fn_is_zero(iv)) goto err; ++j;
	sm9_fn_add(r, x, y); if (!sm9_bn_equ_hex(r, hex_fn_add)) goto err; ++j;
	sm9_fn_sub(r, x, y); if (!sm9_bn_equ_hex(r, hex_fn_sub)) goto err; ++j;
	sm9_fn_sub(r, y, x); if (!sm9_bn_equ_hex(r, hex_fn_nsub)) goto err; ++j;
	sm9_fn_mul(r, x, y); if (!sm9_bn_equ_hex(r, hex_fn_mul)) goto err; ++j;
	sm9_fn_pow(r, x, y); if (!sm9_bn_equ_hex(r, hex_fn_pow)) goto err; ++j;
	sm9_fn_inv(r, x);    if (!sm9_bn_equ_hex(r, hex_fn_inv)) goto err; ++j;

	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

#define hex_iv2 	"123456789abcdef00fedcba987654321123456789abcdef00fedcba987654321-a39654024e243d806e492768664a2b72d632457dd14f49a9f1fdd299c9bb073c"
#define hex_fp2_add	"0074a3145c65ac547541612178e584a902248740e70606dcaaafe2bcbd2f6a21-1b6ac9eb2c47b62cf61608b26c3c7e20674a48c4c509ac130bbaf6d47d32c07c"
#define hex_fp2_dbl	"2ea136125d08b824cd741a4c597dcdda0e6d52df468f917b0adb8ed709d7d72c-995e51aa30d8d45ae85f34da84c0589f6dece1e633b92146debbdc23afe20a11"
#define hex_fp2_tri	"45f1d11b8b8d1437342e2772863cb4c715a3fc4ee9d75a38904956428ec3c2c2-8aed7a7f47f36b0f718cf99fcc59214c93ea0933c0583a7c5b61fca1962a6c5b"
#define hex_fp2_sub	"2e2c92fe00a30bd05832b92ae09849310c48cb9e5f898a9e602bac1a4ca86d0b-7df387bf04911e2df2492c281883da7f06a299216eaf7533d300e54f32af4995"
#define hex_fp2_neg	"9eef64f6d41f4adf6f499e29c8cfe0581abbe9db7733261e6001d3bc5e6559e7-0e70d72ae8e5694b76d23b3ab8673752da02d8b27360e6ca8359df8219b79db6"
#define hex_fp2_mul	"192eb5c3350a03e4baf23dd035b8804af8d5189c710adda53edd9cc0633f2d67-27fe3a559abcc3e1b1fc3f1eb35b4bd5e465f0ef2bcb9997b36e3548637456b6"
#define hex_fp2_mul_u	"27fe3a559abcc3e1b1fc3f1eb35b4bd5e465f0ef2bcb9997b36e3548637456b6-83e29479988f9f28601f2faf8a1dc6af304862123865339167b461a71cd2eaaf"
#define hex_fp2_mul_fp	"546e5945201b73c6ae44053114761efe351d5884c737301cfc7d2376d349a616-3c2f6327ef1c5aa1d06e8cebc4100f0758c04476f40e8a0facb0a0bf09a9dd42"
#define hex_fp2_sqr	"8896d4306fb19d0e4a0e09899240e35cafed70bebb3ad56cf7b07964fefdfb93-16bd622a907d7a92e475ed336e8ebca2cc1e38dd2ae69aaf2a96208eba0ee06e"
#define hex_fp2_sqr_u	"16bd622a907d7a92e475ed336e8ebca2cc1e38dd2ae69aaf2a96208eba0ee06e-5b52579f25e413c717eb438cc69bc7d0e40a4518be8032dddb7e4385c8a693d4"
#define hex_fp2_inv	"93ceda7dddd537eb9307a06313598e650a568d931d16ab98ca0a7483c3b502e2-6face8b958e2bdc0771fd9d700f2703f881ef0d13509f16937f0a0c344647175"
#define hex_fp2_div	"ad68ff7c507f2d4e1cc6cd973c6b821906b9f5937a04fdedc84af1f75f97d00b-8a84a35da11d401c8dca50a572ce7a8c99e7117c45d251f57a2418613dab16bb"
#define hex_fp2_div2	"0ba84d8497422e09335d0693165f7376839b54b7d1a3e45ec2b6e3b5c275f5cb-af07946a8e30f24c1a9a8db2995b2b9bb4f126f1e0ca7b76a3c2ab66d67576a2"

int test_sm9_fp2() {
	const SM9_TWIST_POINT _P2 = {
		{{0xAF82D65B, 0xF9B7213B, 0xD19C17AB, 0xEE265948, 0xD34EC120, 0xD2AAB97F, 0x92130B08, 0x37227552},
		 {0xD8806141, 0x54806C11, 0x0F5E93C4, 0xF1DD2C19, 0xB441A01F, 0x597B6027, 0x78640C98, 0x85AEF3D0}},
		{{0xC999A7C7, 0x6215BBA5, 0xA71A0811, 0x47EFBA98, 0x3D278FF2, 0x5F317015, 0x19BE3DA6, 0xA7CF28D5},
		 {0x84EBEB96, 0x856DC76B, 0xA347C8BD, 0x0736A96F, 0x2CBEE6ED, 0x66BA0D26, 0x2E845C12, 0x17509B09}},
		{{1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0}},
	};
	const SM9_TWIST_POINT *P2 = &_P2;
	const SM9_TWIST_POINT _Ppubs = {
		{{0x96EA5E32, 0x8F14D656, 0x386A92DD, 0x414D2177, 0x24A3B573, 0x6CE843ED, 0x152D1F78, 0x29DBA116},
		 {0x1B94C408, 0x0AB1B679, 0x5E392CFB, 0x1CE0711C, 0x41B56501, 0xE48AFF4B, 0x3084F733, 0x9F64080B}},
		{{0xB4E3216D, 0x0E75C05F, 0x5CDFF073, 0x1006E85F, 0xB7A46F74, 0x1A7CE027, 0xDDA532DA, 0x41E00A53},
	         {0xD0EF1C25, 0xE89E1408, 0x1A77F335, 0xAD3E2FDB, 0x47E3A0CB, 0xB57329F4, 0xABEA0112, 0x69850938}},
		{{1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0}},
	};
	const SM9_TWIST_POINT *Ppubs = &_Ppubs;
	sm9_fp2_t x;
	sm9_fp2_t y;
	sm9_fp2_t r;
	sm9_fp2_t s;
	sm9_fp_t k;
	int j = 1;

	sm9_fp2_copy(x, P2->Y);
	sm9_fp2_copy(y, Ppubs->X);
	sm9_bn_from_hex(k, hex_iv);

	sm9_fp2_t iv2 = {{0xc9bb073c, 0xf1fdd299, 0xd14f49a9, 0xd632457d, 0x664a2b72, 0x6e492768, 0x4e243d80, 0xa3965402},
	                 {0x87654321, 0x0fedcba9, 0x9abcdef0, 0x12345678, 0x87654321, 0x0fedcba9, 0x9abcdef0, 0x12345678}};
	sm9_fp2_from_hex(r, hex_iv2); if (!sm9_fp2_equ(r, iv2)) goto err; ++j;

	sm9_fp2_add(r, x, y);    sm9_fp2_from_hex(s, hex_fp2_add); if (!sm9_fp2_equ(r, s)) goto err; ++j;
	sm9_fp2_dbl(r, x);       sm9_fp2_from_hex(s, hex_fp2_dbl); if (!sm9_fp2_equ(r, s)) goto err; ++j;
	sm9_fp2_tri(r, x);       sm9_fp2_from_hex(s, hex_fp2_tri); if (!sm9_fp2_equ(r, s)) goto err; ++j;
	sm9_fp2_sub(r, x, y);    sm9_fp2_from_hex(s, hex_fp2_sub); if (!sm9_fp2_equ(r, s)) goto err; ++j;
	sm9_fp2_neg(r, x);       sm9_fp2_from_hex(s, hex_fp2_neg); if (!sm9_fp2_equ(r, s)) goto err; ++j;
	sm9_fp2_mul(r, x, y);    sm9_fp2_from_hex(s, hex_fp2_mul); if (!sm9_fp2_equ(r, s)) goto err; ++j;
	sm9_fp2_mul_u(r, x, y);  sm9_fp2_from_hex(s, hex_fp2_mul_u); if (!sm9_fp2_equ(r, s)) goto err; ++j;
	sm9_fp2_mul_fp(r, x, k); sm9_fp2_from_hex(s, hex_fp2_mul_fp); if (!sm9_fp2_equ(r, s)) goto err; ++j;
	sm9_fp2_sqr(r, x);       sm9_fp2_from_hex(s, hex_fp2_sqr); if (!sm9_fp2_equ(r, s)) goto err; ++j;
	sm9_fp2_sqr_u(r, x);     sm9_fp2_from_hex(s, hex_fp2_sqr_u); if (!sm9_fp2_equ(r, s)) goto err; ++j;
	sm9_fp2_inv(r, x);       sm9_fp2_from_hex(s, hex_fp2_inv); if (!sm9_fp2_equ(r, s)) goto err; ++j;
	sm9_fp2_div(r, x, y);    sm9_fp2_from_hex(s, hex_fp2_div); if (!sm9_fp2_equ(r, s)) goto err; ++j;
	sm9_fp2_div2(r, x);      sm9_fp2_from_hex(s, hex_fp2_div2); if (!sm9_fp2_equ(r, s)) goto err; ++j;

	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

#define hex_iv4 \
	"123456789abcdef00fedcba987654321123456789abcdef00fedcba987654321\n" \
	"a39654024e243d806e492768664a2b72d632457dd14f49a9f1fdd299c9bb073c\n" \
	"123456789abcdef00fedcba987654321123456789abcdef00fedcba987654321\n" \
	"a39654024e243d806e492768664a2b72d632457dd14f49a9f1fdd299c9bb073c"
#define hex_fp4_mul \
	"11d8f3dc2c4a7cd3ff4d557d86871210cff65187190711430b2d898affd61cda\n" \
	"960ee85c0aaacd6cc805053293a4955245ba973c9972b6767d0c68450a905ee7\n" \
	"ac9891b21d82827f6ccc2cd8524179b833239019c0b66cad89d7d8735ee03782\n" \
	"8f456b1cee442d189d01fc42fff7fd8481173dae8dc547d85c01a843005a063e"
#define hex_fp4_mul_fp \
	"413b76fe8748ab9130dc2907a55c15da925b496395c2cd82d6311863a4d9cfa8\n" \
	"5cc754d5318f3ed489db7e53f94f3878a527053693983f4d4a61b30f6ea74984\n" \
	"6769891769934201aa8d6de63cc012ec2b722d7b0ad9c9039246a3eea6f3d479\n" \
	"408d33e58a4d3bfaf1d84a7ddad4e4026ca41f2aaa179611d9894584baed89d0"
#define hex_fp4_mul_fp2 \
	"242956015bdff53db568b970d64a7de56a0506309e1309b283317134dd52d53e\n" \
	"5333c472d44677df131eeb1180badb3e1e9f88ba58190d16a92d95f939efb2c3\n" \
	"0ccdaa76a6876ff69de6792161b614ca720bfcee2d5521533fbb28179ec0e31e\n" \
	"2a2d6b832e919c313920f2e13e822795e2ceda8c0d8f4abe78220e4e00aeb6fd"
#define hex_fp4_mul_v \
	"ac9891b21d82827f6ccc2cd8524179b833239019c0b66cad89d7d8735ee03782\n" \
	"8f456b1cee442d189d01fc42fff7fd8481173dae8dc547d85c01a843005a063e\n" \
	"960ee85c0aaacd6cc805053293a4955245ba973c9972b6767d0c68450a905ee7\n" \
	"928e1847aa0ead49d7690054e880a3238205f03ce86ccc55cf148811e3a50bc9"
#define hex_fp4_sqr \
	"8d3bc7848d4ad61017a7cb4efc280103bfe558e240c46c5765f1a4e2ec2e8c54\n" \
	"2f0f2ef9dd3979c7018b67837ba6e73938ba88ae66a101aaa0cf27ee449835ec\n" \
	"93838cbf9e5be34562c5bc031e27357d206f783837a6a921cbf4829292b69441\n" \
	"3681ecc58b68ffc15af31c5b1f1e10e1f3c60bdabb329c0dc7ffb2cc3925f005"
#define hex_fp4_sqr_v \
	"93838cbf9e5be34562c5bc031e27357d206f783837a6a921cbf4829292b69441\n" \
	"3681ecc58b68ffc15af31c5b1f1e10e1f3c60bdabb329c0dc7ffb2cc3925f005\n" \
	"2f0f2ef9dd3979c7018b67837ba6e73938ba88ae66a101aaa0cf27ee449835ec\n" \
	"520870f6eab1a1c37cb7c001f2cd8c82c41a74d1b36d0508fefbec89ee457252"
#define hex_fp4_inv \
	"1ec69309f84c5ad450750826fc804b72fb89fb48474222ba05be08bb1765f1d6\n" \
	"3f16de331f77f510a3ec06e79319e3be5b3777471f79cd53404652b485133e99\n" \
	"1cbf7f3bb04e2389184eade12de2752711cbff452363d2dfaf2bfef40618cebc\n" \
	"3a70e829b83dc311970bc8d3e3e652f88a1ecd49b4672aa18c1c613c9a97d86f"

int test_sm9_fp4() {
	const SM9_TWIST_POINT _Ppubs = {
		{{0x96EA5E32, 0x8F14D656, 0x386A92DD, 0x414D2177, 0x24A3B573, 0x6CE843ED, 0x152D1F78, 0x29DBA116},
		 {0x1B94C408, 0x0AB1B679, 0x5E392CFB, 0x1CE0711C, 0x41B56501, 0xE48AFF4B, 0x3084F733, 0x9F64080B}},
		{{0xB4E3216D, 0x0E75C05F, 0x5CDFF073, 0x1006E85F, 0xB7A46F74, 0x1A7CE027, 0xDDA532DA, 0x41E00A53},
	         {0xD0EF1C25, 0xE89E1408, 0x1A77F335, 0xAD3E2FDB, 0x47E3A0CB, 0xB57329F4, 0xABEA0112, 0x69850938}},
		{{1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0}},
	};
	const SM9_TWIST_POINT *Ppubs = &_Ppubs;
	sm9_fp4_t x;
	sm9_fp4_t y;
	sm9_fp4_t r;
	sm9_fp4_t s;
	sm9_fp2_t q;
	sm9_fp_t k;
	int j = 1;

	sm9_fp2_from_hex(x[0], hex_fp2_mul_fp);
	sm9_fp2_from_hex(x[1], hex_fp2_sqr);
	sm9_fp2_from_hex(y[0], hex_fp2_add);
	sm9_fp2_from_hex(y[1], hex_fp2_tri);
	sm9_bn_from_hex(k, hex_iv);
	sm9_fp2_copy(q, Ppubs->X);

	sm9_fp4_t iv4 = {{{0xc9bb073c, 0xf1fdd299, 0xd14f49a9, 0xd632457d, 0x664a2b72, 0x6e492768, 0x4e243d80, 0xa3965402},
	                  {0x87654321, 0x0fedcba9, 0x9abcdef0, 0x12345678, 0x87654321, 0x0fedcba9, 0x9abcdef0, 0x12345678}},
			 {{0xc9bb073c, 0xf1fdd299, 0xd14f49a9, 0xd632457d, 0x664a2b72, 0x6e492768, 0x4e243d80, 0xa3965402},
	                  {0x87654321, 0x0fedcba9, 0x9abcdef0, 0x12345678, 0x87654321, 0x0fedcba9, 0x9abcdef0, 0x12345678}}};
	sm9_fp4_from_hex(r, hex_iv4); if (!sm9_fp4_equ(r, iv4)) goto err; ++j;

	sm9_fp4_mul(r, x, y);        sm9_fp4_from_hex(s, hex_fp4_mul); if (!sm9_fp4_equ(r, s)) goto err; ++j;
	sm9_fp4_mul_fp(r, x, k);     sm9_fp4_from_hex(s, hex_fp4_mul_fp); if (!sm9_fp4_equ(r, s)) goto err; ++j;
	sm9_fp4_mul_fp2(r, x, q);    sm9_fp4_from_hex(s, hex_fp4_mul_fp2); if (!sm9_fp4_equ(r, s)) goto err; ++j;
	sm9_fp4_mul_v(r, x, y);      sm9_fp4_from_hex(s, hex_fp4_mul_v); if (!sm9_fp4_equ(r, s)) goto err; ++j;
	sm9_fp4_sqr(r, x);           sm9_fp4_from_hex(s, hex_fp4_sqr); if (!sm9_fp4_equ(r, s)) goto err; ++j;
	sm9_fp4_sqr_v(r, x);         sm9_fp4_from_hex(s, hex_fp4_sqr_v); if (!sm9_fp4_equ(r, s)) goto err; ++j;
	sm9_fp4_inv(r, x);           sm9_fp4_from_hex(s, hex_fp4_inv); if (!sm9_fp4_equ(r, s)) goto err; ++j;

	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

#define hex_fp12_mul \
	"058d43459faee14ba2b6a69ff2d8c3ad933a1253e1764dedf5419b144a2ab82b\n" \
	"20ef84805ba02ef92a48fb2ae8086e566a644ab0639249f175268f18d8091ad4\n" \
	"83cc3be54a699ae24d8f920c87baa395befb424a6dcad1dcdfc2a006765ef8d5\n" \
	"1d705169165d9c2386c3bc673df3fa84975afa955a7be27f1b362000a96b8c2c\n" \
	"22b910d826f02961ff0fed439beb1e91f45193f87c2cdd9562da539290846ace\n" \
	"2c618991ae82d35063cfed629ff7d930b8070ba07d0652ba092f046e133e3491\n" \
	"137bc78a9aa182330bd71fb8859314422dd36f5e3c1f6fd36d6c9685fc39419f\n" \
	"8d83e7380abe10a2f3677864c2dbbcdad7ae5434e92043a2da3b71f3f9cedd8c\n" \
	"850c0562ac08996c05d22ea466cf4b1fa7a7064d4653b5fa725d623254bf7125\n" \
	"6dc41016b3ab9b44a4841aa8037e3b4d331cc7c8313abee0c5111a9be5915e90\n" \
	"6d1a15e5b765c4b139bf5c6c4a87214c269b26fb709ff5de885c053f405cf626\n" \
	"8d4d853489a4a5d809fa77e35627a5351651b926f001e1ee46e95808f9001d24"
#define hex_fp12_sqr \
	"3592cba3482fb39756b2ed1d3d756685caa005bd5e8288bc92841d29276aa321\n" \
	"8e3a49919e6de83b1ab1a5bb9eb993c3bbd68e8d305aed5c0b88cef0ef41c47f\n" \
	"3d3d9cc8e07619efd21745f6938a26f7cb0a83ad4aa3a9d066e18ad99833e3ac\n" \
	"25195ec7af551c42d7d37a0b120607d4adba6b9377299688b92a8393f3b8c20f\n" \
	"76f676d5d2cb8d1a2cc237fc78c8d544bef1cd560e654236f502aed0d8c9148c\n" \
	"6cde174a5e9d117175a4a163f041b65f868dffa05b5f3474f729b87f92493f2c\n" \
	"667a86d73e8f88a81306f7f0cd28789a55bf7e9cbe155fc6abb300ad027d8801\n" \
	"a49a66d48ec2ef72a9929413a40e316a8aee1d6236a1db8c56496524f1c23f11\n" \
	"1684bc9679aaba4afe35ec8c0852e438f41e15ab37620d9661018f90fe7415f1\n" \
	"8d37fb8b7edf942885b3009cf7e295bea89444d34091fc57380c778395b7c4e4\n" \
	"278b9d9ea61b6b2758e758ed9a64034576b520e65a9d276a0c82f079501a226e\n" \
	"01a333fa4177601de7cd8ed49ea4906f30e23988dcb7cde173da48499fce3ee5"
#define hex_fp12_inv \
	"47ae900b90945e31afde7fe09f0b69640c468a1648ee52070584a5d13af22bb9\n" \
	"8f273655182c3a9f184dc30421161ecdd50655c36a9266c7df1016e410f34102\n" \
	"a26e789013203804b5f8f1c5a51dd3fb50176d41108b235d6e66712721060252\n" \
	"090aaed5cb83068a0376c6eaca210007744d00c8b4ce53279a67cc069cc519e7\n" \
	"80ab89aa446df59ffe2f29cdb917b760d740ceb634c731b93bf1661aa5868b54\n" \
	"1e13ab51b3198619cc0016599562ed4d266d1481d0d273d3f97cffe5f8e0dd21\n" \
	"5aeb8ed89aafc971a857b8d02f3e3c37ef15ba0e3220e3a7c13c9da8af0c393b\n" \
	"518c338b1430e3129c2555650e5d5634d89513f694ba3a5f2aeb444c540f125a\n" \
	"aba8c5682695f3feee64772d0e49b432c96470e7d663098e9c271a91d4fc991a\n" \
	"0ed800dabe29af5fb41a41cc49fd4084deb02442e8e66f88186607f46395e533\n" \
	"a31b642cd5453c7bb16c82bc67bd3b66fa4db58b8e9aa45f9b579860f18d402c\n" \
	"798b84002e95753e3b07027a8d68b0a7ab2ac40328fc7ca3ea40780b3428dbc1"
#define hex_fp12_pow \
	"43291d68970ec9c00ed4616b8fa4b2b332c15a6e4ed833a4b1d68db20a06896c\n" \
	"48f861508cb878a1f1f806a486f3aa6889571bd5fb1010d73933550d219afd14\n" \
	"34b20766a4cc466efe1ee0d48206d683890494aec331d5b345e9a9adb5c5845a\n" \
	"0e3edea737b3db1083b776eb48e7bfaa4256a8d37d7ab13a370d7682daaf794d\n" \
	"9808adfd960da7837736fca5acb13a84d56962a21af424e48c0aa52c77dfd157\n" \
	"a8aa94ea4f3026eed8fa99ab9a793468db12bb7256c50570e72e375f981861a1\n" \
	"3fd308b4cdcec640fa4f17aac455b2f3daed3fb86a850b47c301c3941dbd6c4c\n" \
	"11b99f09fa20368e840c3d76e706939e4a3e8367165bb802de43acc83ae622d5\n" \
	"a5e97a50168650cae7b02b4c2511eeb194cd5ea5ff02a0284abd5961b46d47e4\n" \
	"b52a91d96353ef501bdbe6424ea26414faeeb930b9e618c2882a85d1fdeea3d0\n" \
	"6c78632b7dbbbdbf347a3f5fd6935a9f9b425125b7ac106e3586a7fbee3f2f20\n" \
	"6b35df1d1153684f1363fce020088a797802e18959df4f006bc5d7f4a632e9f9"

int test_sm9_fp12() {
	sm9_fp12_t x;
	sm9_fp12_t y;
	sm9_fp12_t r;
	sm9_fp12_t s;
	sm9_bn_t k;
	int j = 1;

	sm9_fp4_from_hex(x[0], hex_fp4_mul);
	sm9_fp4_from_hex(x[1], hex_fp4_mul_fp);
	sm9_fp4_from_hex(x[2], hex_fp4_mul_fp2);
	sm9_fp4_from_hex(y[0], hex_fp4_mul_v);
	sm9_fp4_from_hex(y[1], hex_fp4_sqr);
	sm9_fp4_from_hex(y[2], hex_fp4_inv);
	sm9_bn_from_hex(k, hex_iv);

	sm9_fp12_mul(r, x, y); sm9_fp12_from_hex(s, hex_fp12_mul); if (!sm9_fp12_equ(r, s)) goto err; ++j;
	sm9_fp12_sqr(r, x);    sm9_fp12_from_hex(s, hex_fp12_sqr); if (!sm9_fp12_equ(r, s)) goto err; ++j;
	sm9_fp12_inv(r, x);    sm9_fp12_from_hex(s, hex_fp12_inv); if (!sm9_fp12_equ(r, s)) goto err; ++j;
	sm9_fp12_pow(r, x, k); sm9_fp12_from_hex(s, hex_fp12_pow); if (!sm9_fp12_equ(r, s)) goto err; ++j;

	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

#define hex_point1	"917be49d159184fba140f4dfc5d653464e94f718fe195b226b3f715829e6e768-288578d9505d462867a50acee40ee143b896e72505be10e8ce4c6b0c945b642b"
#define hex_point2	"593417680f252445fd0522383e23c77a54b11fe222de4a886eabc26e16bffa3c-38e8fc9a8b60f5ba0c6c411f721c117044435a833757d8fee65828511b8b245d"
#define hex_point_dbl	"268def7968f1e8c51635e277425403df88355fb2ecf16f7920f112eb2a7e50c9-5c596b534bbaa85c1d3aecf436e61ff1bfd9f70856f0309c2a63d8248205d84e"
#define hex_point_add	"056610cb69f8d5659ea94e4a67bbf3b93fb0bd449672d7ca2525ec3b68c894d1-88f3f99ce78ed3ffe6ca1cface5242570cb5d053f16a8e0baae10414babd86a7"
#define hex_point_neg	"917be49d159184fba140f4dfc5d653464e94f718fe195b226b3f715829e6e768-8dba8726b24660c96e5ea081117fe601695bac2614bcddf31723301b4ef5e152"
#define hex_point_sub	"29e4a54cad98da9939b95f677784bff3b1dd9334c83d93e351e0f8f7c4ce2dc5-4473eba3b8ff990b8456c41ec0727b76cb2b0f960495b144949f70bf95643b82"
#define hex_point_mul	"997fcff625adbae62566f684f9e89181713f972c5a9cd9ce6764636761ba87d1-8142a28d1bd109501452a649e2d68f012e265460e0c7d3da743fb036eb23b03b"
#define hex_point_mul_g	"7cf689748f3714490d7a19eae0e7bfad0e0182498b7bcd8a6998dfd00f59be51-4e2e98d190e9d775e0caa943196bfb066d9c30818b2d768fb5299e7135830a6f"

int test_sm9_point() {
	SM9_POINT p;
	SM9_POINT q;
	SM9_POINT r;
	SM9_POINT s;
	sm9_bn_t k;
	int j = 1;
	uint8_t buf[65];			

	sm9_bn_from_hex(k, hex_iv);

	sm9_point_from_hex(&p, hex_point1); if (!sm9_point_is_on_curve(&p)) goto err; ++j;
	sm9_point_from_hex(&q, hex_point2); if (!sm9_point_is_on_curve(&q)) goto err; ++j;
	sm9_point_dbl(&r, &p);     sm9_point_from_hex(&s, hex_point_dbl); if (!sm9_point_equ(&r, &s)) goto err; ++j;
	sm9_point_add(&r, &p, &q); sm9_point_from_hex(&s, hex_point_add); if (!sm9_point_equ(&r, &s)) goto err; ++j;
	sm9_point_neg(&r, &p);     sm9_point_from_hex(&s, hex_point_neg); if (!sm9_point_equ(&r, &s)) goto err; ++j;
	sm9_point_sub(&r, &p, &q); sm9_point_from_hex(&s, hex_point_sub); if (!sm9_point_equ(&r, &s)) goto err; ++j;
	sm9_point_mul(&r, k, &p);  sm9_point_from_hex(&s, hex_point_mul); if (!sm9_point_equ(&r, &s)) goto err; ++j;
	sm9_point_mul_generator(&r, k); sm9_point_from_hex(&s, hex_point_mul_g); if (!sm9_point_equ(&r, &s)) goto err; ++j;

	sm9_point_to_uncompressed_octets(&p, buf);
	sm9_point_from_uncompressed_octets(&q, buf);
	if (!sm9_point_equ(&p, &q)) {
		error_print();
		return -1;
	}





	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

#define hex_tpoint1 \
	"83f6a65d85d51ec72eacf19bc38384e0369eb22a134a725a0191faa6e4f192ef\n" \
	"9a79bfd491ef1cb32d9b57f7d0590ccff6b1cfe63dd15c0823d692fafbe96dbc\n" \
	"9ed11c499291db0454d738555af0ce8a1df960056ee7425a6bf296eae60a5037\n" \
	"849d4434eb7113fc9fb3809b51d54064fa2f20503423d256bc044905b1eba3fb"
#define hex_tpoint2 \
	"a36232a9713f69157b7cdceef54aa0237b3ba0642a80dbb597af8935aea2c130\n" \
	"624b19114e49f00281e2aee1f1b9d4f0a081a135868f8bbdb7b7a7b7da5fd6bc\n" \
	"77966917ec1c5a294dd836c34691ab5e891f8c9f017443902c0a73ec54d449d8\n" \
	"1be45454b6fa085a53744b22fd398238e400c3e031c8796e59e1bd6222048af0"
#define hex_tpoint_neg \
	"83f6a65d85d51ec72eacf19bc38384e0369eb22a134a725a0191faa6e4f192ef\n" \
	"9a79bfd491ef1cb32d9b57f7d0590ccff6b1cfe63dd15c0823d692fafbe96dbc\n" \
	"176ee3b67011cbed812c72fa9a9df8bb03f93345ab93ac81797d043cfd46f546\n" \
	"31a2bbcb173292f536502ab4a3b986e027c372fae6571c85296b52223165a182"
#define hex_tpoint_dbl \
	"73cbced58a8e76ef5235b480050a74e906e4d27185bd85d7ebdcd43ad24475fd\n" \
	"58400f0eb23000d814f5b5d0706749a72909795b7b04f26d6d58b2cf478ad9c9\n" \
	"19b460e09ac9ddbb380d6441e078a47bfcaa7d4c3d60b3a6c0d05f896472dc3c\n" \
	"1d69f785f47d6f25cb901b131612c37edc5e89ee9ba2dac8c401ced40e340a39"
#define hex_tpoint_add \
	"5f443752a19e368f404b89abae20a386d2b534c424b93ededdbfd04d4c569e6b\n" \
	"a411bbd84ee92a6ee53e5ca9cb81bacc192c6ba406f6fdcb2b04d0ab9c42ae44\n" \
	"6a3dadfcaac134e8353dd3abf37d487b206ca28dfab1e0a9376649df748f1605\n" \
	"4fa25e5e6100a023d4923df385dd236749c6a7f8e68db55e0bd1e2263fc04d28"
#define hex_tpoint_sub \
	"3cbbf5fcc6c11a3579036e617bbf0b2861c53979f01e37f59fc4a10d991ccde7\n" \
	"1e9c3c99524c7867c9dbc4f52fdc938cf5aa4a980d3905cc91a5b91331235290\n" \
	"44027c5d814bab73ad93d14b564303aab153ad7355bcfbf8a8bed7cb577e7fd8\n" \
	"47a4037d1d6f6d2014aa04292fa91cf07b1f4331a85d4b66a6e048226ddfc43e"
#define hex_tpoint_mul \
	"5d704de3261290dbba39dbd14e6bc416025240fd1ed65ec982efed685ae41e8b\n" \
	"705c9ca4b5ef465c4e5db80ca4880627a6d9d6bcefd4756496baba9d5eaa3304\n" \
	"4e96eb3543aabf1e9a65cae24177b9d13b0f7fae9472145ba7ae2b14bb447aef\n" \
	"5d7ba50d7eac49a00b18fee2069afd3cc9719993fa78271e66b7a3efed46ac8b"
#define hex_tpoint_mulg \
	"920ef6fb3a2acff52aa0c004c18feca149dfd33d98086f8f402ea9e0de303c49\n" \
	"1f97dd359f2b065d63e0987f5bea2f3dc865c2cc112d7d161b46b83451716fd8\n" \
	"614881d4d05fef3173a4990465876c5200f58c5015e13354b23ae401c20c4aef\n" \
	"18a22e02b7d395a49f0646a79438e79cd37c32f163fe8923c13d56bab668e8a7"

int test_sm9_twist_point() {
	SM9_TWIST_POINT p;
	SM9_TWIST_POINT q;
	SM9_TWIST_POINT r;
	SM9_TWIST_POINT s;
	sm9_bn_t k;
	int j = 1;

	sm9_bn_from_hex(k, hex_iv);

	sm9_twist_point_from_hex(&p, hex_tpoint1); if (!sm9_twist_point_is_on_curve(&p)) goto err; ++j;
	sm9_twist_point_from_hex(&q, hex_tpoint2); if (!sm9_twist_point_is_on_curve(&q)) goto err; ++j;
	sm9_twist_point_neg(&r, &p);     sm9_twist_point_from_hex(&s, hex_tpoint_neg); if (!sm9_twist_point_equ(&r, &s)) goto err; ++j;
	sm9_twist_point_dbl(&r, &p);     sm9_twist_point_from_hex(&s, hex_tpoint_dbl); if (!sm9_twist_point_equ(&r, &s)) goto err; ++j;
	sm9_twist_point_add(&r, &p, &q); sm9_twist_point_from_hex(&s, hex_tpoint_add); if (!sm9_twist_point_equ(&r, &s)) goto err; ++j;
	sm9_twist_point_add_full(&r, &p, &q); if (!sm9_twist_point_equ(&r, &s)) goto err; ++j;
	sm9_twist_point_sub(&r, &p, &q); sm9_twist_point_from_hex(&s, hex_tpoint_sub); if (!sm9_twist_point_equ(&r, &s)) goto err; ++j;
	sm9_twist_point_mul(&r, k, &p);  sm9_twist_point_from_hex(&s, hex_tpoint_mul); if (!sm9_twist_point_equ(&r, &s)) goto err; ++j;
	sm9_twist_point_mul_generator(&r, k);    sm9_twist_point_from_hex(&s, hex_tpoint_mulg); if (!sm9_twist_point_equ(&r, &s)) goto err; ++j;

	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

#define hex_pairing1 \
	"4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d\n" \
	"28b3404a61908f5d6198815c99af1990c8af38655930058c28c21bb539ce0000\n" \
	"38bffe40a22d529a0c66124b2c308dac9229912656f62b4facfced408e02380f\n" \
	"a01f2c8bee81769609462c69c96aa923fd863e209d3ce26dd889b55e2e3873db\n" \
	"67e0e0c2eed7a6993dce28fe9aa2ef56834307860839677f96685f2b44d0911f\n" \
	"5a1ae172102efd95df7338dbc577c66d8d6c15e0a0158c7507228efb078f42a6\n" \
	"1604a3fcfa9783e667ce9fcb1062c2a5c6685c316dda62de0548baa6ba30038b\n" \
	"93634f44fa13af76169f3cc8fbea880adaff8475d5fd28a75deb83c44362b439\n" \
	"b3129a75d31d17194675a1bc56947920898fbf390a5bf5d931ce6cbb3340f66d\n" \
	"4c744e69c4a2e1c8ed72f796d151a17ce2325b943260fc460b9f73cb57c9014b\n" \
	"84b87422330d7936eaba1109fa5a7a7181ee16f2438b0aeb2f38fd5f7554e57a\n" \
	"aab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb"

#define hex_RA \
	"7CBA5B19069EE66AA79D490413D11846B9BA76DD22567F809CF23B6D964BB265\n" \
	"A9760C99CB6F706343FED05637085864958D6C90902ABA7D405FBEDF7B781599"
#define hex_deB \
	"74CCC3AC9C383C60AF083972B96D05C75F12C8907D128A17ADAFBAB8C5A4ACF7\n" \
	"01092FF4DE89362670C21711B6DBE52DCD5F8E40C6654B3DECE573C2AB3D29B2\n" \
	"44B0294AA04290E1524FF3E3DA8CFD432BB64DE3A8040B5B88D1B5FC86A4EBC1\n" \
	"8CFC48FB4FF37F1E27727464F3C34E2153861AD08E972D1625FC1A7BD18D5539"

#define hex_pairing2 \
	"28542FB6954C84BE6A5F2988A31CB6817BA0781966FA83D9673A9577D3C0C134\n" \
	"5E27C19FC02ED9AE37F5BB7BE9C03C2B87DE027539CCF03E6B7D36DE4AB45CD1\n" \
	"A1ABFCD30C57DB0F1A838E3A8F2BF823479C978BD137230506EA6249C891049E\n" \
	"3497477913AB89F5E2960F382B1B5C8EE09DE0FA498BA95C4409D630D343DA40\n" \
	"4FEC93472DA33A4DB6599095C0CF895E3A7B993EE5E4EBE3B9AB7D7D5FF2A3D1\n" \
	"647BA154C3E8E185DFC33657C1F128D480F3F7E3F16801208029E19434C733BB\n" \
	"73F21693C66FC23724DB26380C526223C705DAF6BA18B763A68623C86A632B05\n" \
	"0F63A071A6D62EA45B59A1942DFF5335D1A232C9C5664FAD5D6AF54C11418B0D\n" \
	"8C8E9D8D905780D50E779067F2C4B1C8F83A8B59D735BB52AF35F56730BDE5AC\n" \
	"861CCD9978617267CE4AD9789F77739E62F2E57B48C2FF26D2E90A79A1D86B93\n" \
	"9B1CA08F64712E33AEDA3F44BD6CB633E0F722211E344D73EC9BBEBC92142765\n" \
	"6BA584CE742A2A3AB41C15D3EF94EDEB8EF74A2BDCDAAECC09ABA567981F6437"


#define hex_Ppube \
	"9174542668E8F14AB273C0945C3690C66E5DD09678B86F734C4350567ED06283\n" \
	"54E598C6BF749A3DACC9FFFEDD9DB6866C50457CFC7AA2A4AD65C3168FF74210"
#define rB		"00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE"
#define hex_pairing3 \
	"1052D6E9D13E381909DFF7B2B41E13C987D0A9068423B769480DACCE6A06F492\n" \
	"5FFEB92AD870F97DC0893114DA22A44DBC9E7A8B6CA31A0CF0467265A1FB48C7\n" \
	"2C5C3B37E4F2FF83DB33D98C0317BCBBBBF4AC6DF6B89ECA58268B280045E612\n" \
	"6CED9E2D7C9CD3D5AD630DEFAB0B831506218037EE0F861CF9B43C78434AEC38\n" \
	"0AE7BF3E1AEC0CB67A03440906C7DFB3BCD4B6EEEBB7E371F0094AD4A816088D\n" \
	"98DBC791D0671CACA12236CDF8F39E15AEB96FAEB39606D5B04AC581746A663D\n" \
	"00DD2B7416BAA91172E89D5309D834F78C1E31B4483BB97185931BAD7BE1B9B5\n" \
	"7EBAC0349F8544469E60C32F6075FB0468A68147FF013537DF792FFCE024F857\n" \
	"10CC2B561A62B62DA36AEFD60850714F49170FD94A0010C6D4B651B64F3A3A5E\n" \
	"58C9687BEDDCD9E4FEDAB16B884D1FE6DFA117B2AB821F74E0BF7ACDA2269859\n" \
	"2A430968F16086061904CE201847934B11CA0F9E9528F5A9D0CE8F015C9AEA79\n" \
	"934FDDA6D3AB48C8571CE2354B79742AA498CB8CDDE6BD1FA5946345A1A652F6"


int test_sm9_pairing()
{
	const SM9_POINT _P1 = {
		{0x7c66dddd, 0xe8c4e481, 0x09dc3280, 0xe1e40869, 0x487d01d6, 0xf5ed0704, 0x62bf718f, 0x93de051d},
		{0x0a3ea616, 0x0c464cd7, 0xfa602435, 0x1c1c00cb, 0x5c395bbc, 0x63106512, 0x4f21e607, 0x21fe8dda},
		{1,0,0,0,0,0,0,0}
	};
	const SM9_POINT *P1 = &_P1;

	const SM9_TWIST_POINT _P2 = {
		{{0xAF82D65B, 0xF9B7213B, 0xD19C17AB, 0xEE265948, 0xD34EC120, 0xD2AAB97F, 0x92130B08, 0x37227552},
		 {0xD8806141, 0x54806C11, 0x0F5E93C4, 0xF1DD2C19, 0xB441A01F, 0x597B6027, 0x78640C98, 0x85AEF3D0}},
		{{0xC999A7C7, 0x6215BBA5, 0xA71A0811, 0x47EFBA98, 0x3D278FF2, 0x5F317015, 0x19BE3DA6, 0xA7CF28D5},
		 {0x84EBEB96, 0x856DC76B, 0xA347C8BD, 0x0736A96F, 0x2CBEE6ED, 0x66BA0D26, 0x2E845C12, 0x17509B09}},
		{{1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0}},
	};
	const SM9_TWIST_POINT *P2 = &_P2;

	const SM9_TWIST_POINT _Ppubs = {
		{{0x96EA5E32, 0x8F14D656, 0x386A92DD, 0x414D2177, 0x24A3B573, 0x6CE843ED, 0x152D1F78, 0x29DBA116},
		 {0x1B94C408, 0x0AB1B679, 0x5E392CFB, 0x1CE0711C, 0x41B56501, 0xE48AFF4B, 0x3084F733, 0x9F64080B}},
		{{0xB4E3216D, 0x0E75C05F, 0x5CDFF073, 0x1006E85F, 0xB7A46F74, 0x1A7CE027, 0xDDA532DA, 0x41E00A53},
	         {0xD0EF1C25, 0xE89E1408, 0x1A77F335, 0xAD3E2FDB, 0x47E3A0CB, 0xB57329F4, 0xABEA0112, 0x69850938}},
		{{1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0}},
	};
	const SM9_TWIST_POINT *Ppubs = &_Ppubs;

	SM9_TWIST_POINT p;
	SM9_POINT q;
	sm9_fp12_t r;
	sm9_fp12_t s;
	sm9_bn_t k;
	int j = 1;

	sm9_pairing(r, Ppubs, P1); sm9_fp12_from_hex(s, hex_pairing1); if (!sm9_fp12_equ(r, s)) goto err; ++j;

	sm9_twist_point_from_hex(&p, hex_deB); sm9_point_from_hex(&q, hex_RA);
	sm9_pairing(r, &p, &q); sm9_fp12_from_hex(s, hex_pairing2); if (!sm9_fp12_equ(r, s)) goto err; ++j;

	sm9_bn_from_hex(k, rB); sm9_point_from_hex(&q, hex_Ppube);
	sm9_pairing(r, P2, &q); sm9_fp12_pow(r, r, k); sm9_fp12_from_hex(s, hex_pairing3); if (!sm9_fp12_equ(r, s)) goto err; ++j;

	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

#define hex_ks		"000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4"
#define hex_ds		"A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820-78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3"

int test_sm9_sign() {
	SM9_SIGN_CTX ctx;
	SM9_SIGN_KEY key;
	SM9_SIGN_MASTER_KEY mpk;
	SM9_POINT ds;
	uint8_t sig[1000] = {0};
	size_t siglen = 0;
	int j = 1;

	uint8_t data[20] = {0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
	uint8_t IDA[5] = {0x41, 0x6C, 0x69, 0x63, 0x65};

	sm9_bn_from_hex(mpk.ks, hex_ks); sm9_twist_point_mul_generator(&(mpk.Ppubs), mpk.ks);
	if (sm9_sign_master_key_extract_key(&mpk, (char *)IDA, sizeof(IDA), &key) < 0) goto err; ++j;
	sm9_point_from_hex(&ds, hex_ds); if (!sm9_point_equ(&(key.ds), &ds)) goto err; ++j;

	sm9_sign_init(&ctx);
	sm9_sign_update(&ctx, data, sizeof(data));
	if (sm9_sign_finish(&ctx, &key, sig, &siglen) < 0) goto err; ++j;

	sm9_verify_init(&ctx);
	sm9_verify_update(&ctx, data, sizeof(data));
	if (sm9_verify_finish(&ctx, sig, siglen, &mpk, (char *)IDA, sizeof(IDA)) != 1) goto err; ++j;

	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

#define hex_ke		"0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22"

#define hex_de \
	"94736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683\n" \
	"115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158\n" \
	"7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F\n" \
	"27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1"

int test_sm9_ciphertext()
{
	const SM9_POINT _P1 = {
		{0x7c66dddd, 0xe8c4e481, 0x09dc3280, 0xe1e40869, 0x487d01d6, 0xf5ed0704, 0x62bf718f, 0x93de051d},
		{0x0a3ea616, 0x0c464cd7, 0xfa602435, 0x1c1c00cb, 0x5c395bbc, 0x63106512, 0x4f21e607, 0x21fe8dda},
		{1,0,0,0,0,0,0,0}
	};
	const SM9_POINT *P1 = &_P1;

	SM9_POINT C1;
	uint8_t c2[SM9_MAX_PLAINTEXT_SIZE];
	uint8_t c3[SM3_HMAC_SIZE];
	uint8_t buf[1024];
	uint8_t *p = buf;
	size_t len = 0;

	sm9_point_copy(&C1, P1);
	if (sm9_ciphertext_to_der(&C1, c2, sizeof(c2), c3, &p, &len) != 1) {
		error_print();
		return -1;
	}
	//printf("SM9_MAX_CIPHERTEXT_SIZE %zu\n", len);
	return 1;
}


int test_sm9_encrypt() {
	SM9_ENC_MASTER_KEY msk;
	SM9_ENC_KEY key;
	SM9_TWIST_POINT de;
	uint8_t out[1000] = {0};
	size_t outlen = 0;
	int j = 1;

	uint8_t data[20] = {0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
	uint8_t dec[20] = {0};
	size_t declen = 20;
	uint8_t IDB[3] = {0x42, 0x6F, 0x62};

	sm9_bn_from_hex(msk.ke, hex_ke);
	sm9_point_mul_generator(&(msk.Ppube), msk.ke);

	if (sm9_enc_master_key_extract_key(&msk, (char *)IDB, sizeof(IDB), &key) < 0) goto err; ++j;


	sm9_twist_point_from_hex(&de, hex_de); if (!sm9_twist_point_equ(&(key.de), &de)) goto err; ++j;

	if (sm9_encrypt(&msk, (char *)IDB, sizeof(IDB), data, sizeof(data), out, &outlen) < 0) goto err; ++j;
	if (sm9_decrypt(&key, (char *)IDB, sizeof(IDB), out, outlen, dec, &declen) < 0) goto err; ++j;
	if (memcmp(data, dec, sizeof(data)) != 0) goto err; ++j;

	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

int main(void) {
	if (test_sm9_fp() != 1) goto err;
	if (test_sm9_fn() != 1) goto err;
	if (test_sm9_fp2() != 1) goto err;
	if (test_sm9_fp4() != 1) goto err;
	if (test_sm9_fp12() != 1) goto err;
	if (test_sm9_point() != 1) goto err;
	if (test_sm9_twist_point() != 1) goto err;
	if (test_sm9_pairing() != 1) goto err;
	if (test_sm9_sign() != 1) goto err;
	if (test_sm9_ciphertext() != 1) goto err;
	if (test_sm9_encrypt() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
