#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


/*

GFp192

p BDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F
a BB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985
b 1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1
x 4AD5F7048DE709AD51236DE65E4D4B482C836DC6E4106640
y 02BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2
n BDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677
h 1

GFp256

p 8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a 787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b 63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
x 421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
y 0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
n 8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
h 1

GF2m193 f(x) = x^193 + x^15 + 1

f 2000000000000000000000000000000000000000000008001
a 0
b 002FE22037B624DBEBC4C618E13FD998B1A18E1EE0D05C46FB
x 00D78D47E85C93644071BC1C212CF994E4D21293AAD8060A84
y 00615B9E98A31B7B2FDDEEECB76B5D875586293725F9D2FC0C
n 80000000000000000000000043E9885C46BF45D8C5EBF3A1

GF2m257 f(x) = x^257 + x^12 + 1

f 20000000000000000000000000000000000000000000000000000000000001001
a 0
b 00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B
x 00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD
y 013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E
n 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D

Signature on GFp256

M message digest
d 128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263
Z F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A
e B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76
k 6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F
r 40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1
s 6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7

Signature on GF2m257

M message digest
d 771EF3DBFF5F1CDC32B9C572930476191998B2BF7CB981D7F5B39202645F0931
Z 26352AF82EC19F207BBC6F9474E11E90CE0F7DDACE03B27F801817E897A81FD5
e AD673CBDA311417129A9EAA5F9AB1AA1633AD47718A84DFD46C17C6FA0AA3B12
k 36CD79FC8E24B7357A8A7B4A46D454C397703D6498158C605399B341ADA186D6
r 6D3FBA26EAB2A1054F5D198332E335817C8AC453ED26D3391CD4439D825BF25B
s 3124C5688D95F0A10252A9BED033BEC84439DA384621B6D6FAD77F94B74A9556

Key Agreement on GFp256

A	ALICE123@YAHOO.COM
LA	0090
B	BILL456@YAHOO.COM
LB	0088

dA	6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE
dB	5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53
ZA	E4D1D0C3CA4C7F11BC8FF8CB3F4C02A78F108FA098E51A668487240F75E20F31
ZB	6B4B6D0E276691BD4A11BF72F4FB501AE309FDACB72FA6CC336E6656119ABD67
rA	83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563
x1	6CB5633816F4DD560B1DEC458310CBCC6856C09505324A6D23150C408F162BF0
y1	0D6FCF62F1036C0A1B6DACCF57399223A65F7D7BF2D9637E5BBBEB857961BF1A
rB	33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80
x2	1799B2A2C778295300D9A2325C686129B8F2B5337B3DCF4514E8BBC19D900EE5
y2	54C9288C82733EFDF7808AE7F27D0E732F7C73A7D9AC98B7D8740A91D0DB3CF4
x1'	E856C09505324A6D23150C408F162BF0
x2'	B8F2B5337B3DCF4514E8BBC19D900EE5
tB	2B2E11CBF03641FC3D939262FC0B652A70ACAA25B5369AD38B375C0265490C9F


Encrypt on GFp256

M	encryption standard
d	1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0
k	4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F
C1	0464D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78
C2	650053A89B41C418B0C3AAD00D886C00286467
C3	9C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D

Encrypt on GF2m257

M	encryption standard
d	56A270D17377AA9A367CFA82E46FA5267713A9B91101D0777B07FCE018C757EB
k	6D3B497153E3E92524E5C122682DBDC8705062E20B917A5F8FCDB8EE4C66663D
C1	040083E628CF701EE3141E8873FE55936ADF24963F5DC9C6480566C80F8A1D8CC51B01524C647F0C0412DEFD468BDA3AE0E5A80FCC8F5C990FEE11602929232DCD9F36
C2	FD55AC6213C2A8A040E4CAB5B26A9CFCDA7373FCDA7373
C3	73A48625D3758FA37B3EAB80E9CFCABA665E3199EA15A1FA8189D96F579125E4

*/

RAND_METHOD fake_rand;
const RAND_METHOD *old_rand;

int fbytes(unsigned char *buf, int num)
{
	int ret;
	BIGNUM *tmp = NULL;
	
	if (fbytes_counter >= 8)
		return 0;

	if (!(tmp = BN_new())) {
		return 0;
	}

	if (!BN_hex2bn(&tmp, numbers[fbytes_counter])) {
		BN_free(tmp);
		return 0;
	}

	fbytes_counter++;


	if (num != BN_num_bytes(tmp) || !BN_bn2bin(tmp, buf))
		ret = 0;
	else
		ret = 1;

	if (tmp)
		BN_free(tmp);

	return ret;
}

int change_rand(void)
{
	if (!(old_rand = RAND_get_rand_method())) {
		return 0;
	}

	fake_rand.seed		= old_rand->seed;
	fake_rand.cleanup	= old_rand->cleanup;
	fake_rand.add		= old_rand->add;
	fake_rand.status	= old_rand->status;
	fake_rand.bytes		= fbytes;
	fake_rand.pseudorand	= old_rand->bytes;
	
	if (!RAND_set_rand_method(&fake_rand)) {
		return 0;
	}
	
	return 1;
} 

int restore_rand(void)
{
	if (!RAND_set_rand_method(rand))
		return 0;
	else
		return 1;
}


EC_GROUP *new_ec_group(int is_prime_field,
	const char *p_hex, const char *a_hex, const char *b_hex,
	const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex)
{
	int e = 1;
	EC_GROUP *ec_group = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	EC_POINT *G = NULL;
	point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
	int flag = 0;

	if (!(ctx = BN_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	// FIXME
	if (!(ec_group = EC_GROUP_new(EC_GFp_mont_method()))) {
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

	if (is_prime_curve) {
		if (!EC_GROUP_set_curve_GFp(ec_group, p, a, b, ctx)) {
			ERR_print_errors_fp(stderr);
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GFp(ec_group, G, x, y, ctx)) {
			ERR_print_errors_fp(stderr);
			goto err;
		}

	} else {
		if (!EC_GROUP_set_curve_GF2m(ec_group, p, a, b, ctx)) {
			ERR_print_errors_fp(stderr);
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GF2m(ec_group, G, x, y, ctx)) {
			ERR_print_errors_fp(stderr);
			goto err;
		}
	}

	if (!(G = EC_POINT_new(ec_group))) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	if (!EC_GROUP_set_generator(ec_group, G, n, h)) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	EC_GROUP_set_asn1_flag(ec_group, flag);	
	EC_GROUP_set_point_conversion_form(ec_group, form);

	e = 0;
err:
	if (ctx) BN_CTX_free(ctx);
	if (p) BN_free(p);
	if (a) BN_free(a);
	if (b) BN_free(b);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (n) BN_free(n);
	if (h) BN_free(h);
	if (G) EC_POINT_free(G);
	if (e && ec_group) {
		EC_GROUP_free(ec_group);
		ec_group = NULL;
	}
	return ec_group;
}

EC_KEY *new_ec_key(const EC_GROUP *group, const char *sk, const char *id,
	const char *xP, const char *yP)
{
	EC_KEY *ec_key = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;


	if (sk) {
		if (!BN_hex2bn(&d, sk)) {
			ERR_print_errors_fp(stderr);
			goto err;
		}
	}

	if (id) {
		if (!SM2_set_id(ec_key, id)) {
			ERR_print_errors_fp(stderr);
			goto err;
		}
	}


	if (xP && yP) {
		if (!BN_hex2bn(&x, xP)) {
			ERR_print_errors_fp(stderr);
			goto err;
		}
		if (!BN_hex2bn(&y, yP)) {
		}

		if (!EC_KEY_set_public_key()) {
		}
	}


	
err:
	
	return ec_key;	
}


static int test_sm2_id(void)
{
	int ret = 0;
	EC_GROUP *group = NULL;
	EC_KEY *ec_key = NULL;
	BIGNUM *bn = NULL;
	const char *id[] = {
		"ALICE123@YAHOO.COM",
		"ALICE123@YAHOO.COM",
		"ALICE123@YAHOO.COM",
		"BILL456@YAHOO.COM"};
	const char *sk[] = {
		"128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
		"771EF3DBFF5F1CDC32B9C572930476191998B2BF7CB981D7F5B39202645F0931",
		"6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE",
		"5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53"};
	const char *Z[] = {
		"F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A",
		"26352AF82EC19F207BBC6F9474E11E90CE0F7DDACE03B27F801817E897A81FD5",
		"E4D1D0C3CA4C7F11BC8FF8CB3F4C02A78F108FA098E51A668487240F75E20F31",
		"6B4B6D0E276691BD4A11BF72F4FB501AE309FDACB72FA6CC336E6656119ABD67"};
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned char buf[sizeof(dgst) * 2];
	unsigned int len;
	int i, j;


	if (!(group = new_GFp256test())) {
		goto err;
	}

	if (!(ec_key = EC_KEY_new())) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	if (!EC_KEY_set_group(ec_key, group)) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	if (!(bn = BN_new())) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	for (i = 0; i < sizeof(id)/sizeof(id[0]); i++) {

		if (!SM2_set_id(ec_key, id[i])) {
			ERR_print_errors_fp(stderr);
			goto err;
		}
		
		if (!BN_hex2bn(&bn, sk[i])) {
			ERR_print_errors_fp(stderr);
			goto err;
		}

		if (!EC_KEY_set_private_key(ec_key, bn)) {
			ERR_print_errors_fp(stderr);
			goto err;
		}

		if (!SM2_compute_id_digest(dgst, &dgstlen, EVP_sm3(), ec_key)) {
			ERR_print_errors_fp(stderr);
			goto err;
		}	

		for (j = 0; j < SM3_DIGEST_LENGTH; j++) {	
			sprintf(&(buf[j * 2]), "%02X", dgst[j]);
		}

		if (memcpy(Z[i], buf, strlen(Z[i])) != 0) {
			goto err;
		}
	}

	ret = 1;

err:
	EC_GROUP_free(group);
	EC_KEY_free(ec_key);
	BN_free(bn);
	return ret;
}

static void test_sm2_sign(void)
{
	int rv;
	EC_KEY *ec_key = NULL;
	unsigned char dgst[32];
	ECDSA_SIG *sig = NULL;
	unsigned char sigbuf[128];
	unsigned int siglen;

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	OPENSSL_assert(ec_key);
	rv = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(rv == 1);

	RAND_pseudo_bytes(dgst, sizeof(dgst));
	
	sig = SM2_do_sign(dgst, (int)sizeof(dgst), ec_key);
	OPENSSL_assert(sig);
	rv = SM2_do_verify(dgst, (int)sizeof(dgst), sig, ec_key);
	OPENSSL_assert(rv == 1);

	rv = SM2_sign(0, dgst, sizeof(dgst), sigbuf, &siglen, ec_key);
	OPENSSL_assert(rv == 1);
	rv = SM2_verify(0, dgst, sizeof(dgst), sigbuf, siglen, ec_key);
	OPENSSL_assert(rv == 1);

	EC_KEY_free(ec_key);
	ECDSA_SIG_free(sig);
}

	char *msg = "message digest";
	char *id = "ALICE123@YAHOO.COM";
	char *sk = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
	char *e = "B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76";
	char *k = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
	char *r = "40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1";
	char *s = "6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7";


int test_sm2_sign(const EC_GROUP *group, const char *msg, const char *id,
	const char *sk, const char *e, const char *s)
{
	int ret = 0;
	EC_GROUP *group = NULL;
	unsigned char idgst[32];

	EVP_MD_CTX md_ctx;

	if (!(group = new_GFp256test())) {
		goto err;
	}

	if (!(ec_key = EC_KEY_new())) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	if (!EC_KEY_set_group(ec_key, group)) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	if (!BN_hex2bn(&bn, sk)) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	if (!EC_KEY_set_private_key(ec_key, bn)) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	if (!SM2_set_id(ec_key, id)) {
		ERR_print_errors_fp(stderr);
		goto err;
	}


	
	EVP_MD_CTX_init(&md_ctx);

	
	EVP_DigestInit(&md_ctx, iddgst, sizeof(iddgst));

	EVP_DigestInit(&md_ctx, msg, strlen(msg));

	EVP_DigestFinal(&md_ctx, msgdgst, &len);


	hexequbin(Z, msgdgst, len);

	
	sig = SM2_do_sign();


	hex = BN_bin2hex(sig->r);

	if (strcmp(r, hex)) {
	}

	hex = BN_bin2hex(sig->s);
	
	if (strcmp(s, hex)) {
	}


	SM2_do_verify();

	

	return 0;
}



int test_sm2_sign_GF2m257(void)
{
	int ret = 0;
	char *msg = "message digest";
	char *d = "771EF3DBFF5F1CDC32B9C572930476191998B2BF7CB981D7F5B39202645F0931";
	char *Z = "26352AF82EC19F207BBC6F9474E11E90CE0F7DDACE03B27F801817E897A81FD5";
	char *e = "AD673CBDA311417129A9EAA5F9AB1AA1633AD47718A84DFD46C17C6FA0AA3B12";
	char *k = "36CD79FC8E24B7357A8A7B4A46D454C397703D6498158C605399B341ADA186D6";
	char *r = "6D3FBA26EAB2A1054F5D198332E335817C8AC453ED26D3391CD4439D825BF25B";
	char *s = "3124C5688D95F0A10252A9BED033BEC84439DA384621B6D6FAD77F94B74A9556";
	
	return ret;
}

int hexequbin(const char *hex, const unsigned char *bin, size_t binlen)
{
	char *buf = NULL;
	if (binlen * 2 != strlen(hex)) {
		return 0;
	}

	buf = OPENSSL_malloc(binlen * 2);

	for (i = 0; i < binlen; i++) {
		sprintf(buf + i*2, "%02X", bin[i]);
	}

	if (memcmp(hex, buf, binlen * 2) != 0) {
		return 0;
	} else {
		return 1;
	}
}

EC_KEY *new_ec_key(const EC_GROUP *group, const char *hex)
{
}

int test_sm2_enc(const EC_GROUP *group, const char *msg, const char *sk,
	const char *c1, const char *c2, const char *c3)
{
	int ret = 0;
	EC_KEY *ec_key = NULL;
	SM2_CIPHERTEXT_VALUE *cv = NULL;


	cv = SM2_do_encrypt(EVP_sm3(), EVP_sm3(), (unsigned char *)msg, (size_t)strlen(msg), ec_key);

	
	EC_POINT_point2oct(cv->ephem_point);


	if (!hexequbin(C2, cv->ciphertext, cv->ciphertext_size)) {
		return 0;
	}

	if (!hexequbin(C3, cv->mactag, cv->mactag_size)) {
		return 0;
	}
	
	return ret;
}


int test_sm2()
{
	EC_GROUP *sm2p192test = NULL;
	EC_GROUP *sm2p256test = NULL;
	EC_GROUP *sm2b193test = NULL;
	EC_GROUP *sm2b257test = NULL;

	sm2p192test = new_ec_group(1,
		"BDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F",
		"BB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985",
		"1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1",
		"4AD5F7048DE709AD51236DE65E4D4B482C836DC6E4106640",
		"02BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2",
		"BDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677",
		"1");

	sm2p256test = new_ec_group(1,
		"8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
		"787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
		"63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
		"421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
		"0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
		"8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
		"1");

	sm2b193test = new_ec_group(0,
		"2000000000000000000000000000000000000000000008001",
		"0",
		"002FE22037B624DBEBC4C618E13FD998B1A18E1EE0D05C46FB",
		"00D78D47E85C93644071BC1C212CF994E4D21293AAD8060A84",
		"00615B9E98A31B7B2FDDEEECB76B5D875586293725F9D2FC0C",
		"80000000000000000000000043E9885C46BF45D8C5EBF3A1",
		"1");

	sm2b257test = new_ec_group(0,
		"20000000000000000000000000000000000000000000000000000000000001001",
		"0",
		"00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B",
		"00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD",
		"013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E",
		"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D",
		"1");


	test_sm2_sign(
		sm2p256test,
		"message digest",
		"128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
		"F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A",
		"B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76",
		"6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F",
		"40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1",
		"6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7");

	test_sm2_sign(
		sm2b257test,
		"message digest",
		"771EF3DBFF5F1CDC32B9C572930476191998B2BF7CB981D7F5B39202645F0931",
		"26352AF82EC19F207BBC6F9474E11E90CE0F7DDACE03B27F801817E897A81FD5",
		"AD673CBDA311417129A9EAA5F9AB1AA1633AD47718A84DFD46C17C6FA0AA3B12",
		"36CD79FC8E24B7357A8A7B4A46D454C397703D6498158C605399B341ADA186D6",
		"6D3FBA26EAB2A1054F5D198332E335817C8AC453ED26D3391CD4439D825BF25B",
		"3124C5688D95F0A10252A9BED033BEC84439DA384621B6D6FAD77F94B74A9556");

	test_sm2_enc(
		sm2p256test,
		"encryption standard",
		"1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0",
		"4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F",
		"04"
		"64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE"
		"58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78",
		"650053A89B41C418B0C3AAD00D886C00286467",
		"9C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D");

	test_sm2_enc(
		sm2b257test,
		"encryption standard",
		"56A270D17377AA9A367CFA82E46FA5267713A9B91101D0777B07FCE018C757EB",
		"6D3B497153E3E92524E5C122682DBDC8705062E20B917A5F8FCDB8EE4C66663D",
		"04"
		"0083E628CF701EE3141E8873FE55936ADF24963F5DC9C6480566C80F8A1D8CC51B"
		"01524C647F0C0412DEFD468BDA3AE0E5A80FCC8F5C990FEE11602929232DCD9F36",
		"FD55AC6213C2A8A040E4CAB5B26A9CFCDA7373FCDA7373",
		"73A48625D3758FA37B3EAB80E9CFCABA665E3199EA15A1FA8189D96F579125E4");

	return 0;
}


static void test_sm2_enc(void)
{
	int rv;
	EC_KEY *ec_key = NULL;
	char *msg = "Hello world!";
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	unsigned char ctbuf[512];
	unsigned char ptbuf[512];	
	size_t len, len2;
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);	

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	OPENSSL_assert(ec_key);
	rv = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(rv == 1);

	cv = SM2_do_encrypt(EVP_sm3(), EVP_sm3(), (unsigned char *)msg, (size_t)strlen(msg), ec_key);
	OPENSSL_assert(cv);
	SM2_CIPHERTEXT_VALUE_print(bio, EC_KEY_get0_group(ec_key), cv, 0, 0);

	bzero(ptbuf, sizeof(ptbuf));	
	len = sizeof(ptbuf);
	rv = SM2_do_decrypt(EVP_sm3(), EVP_sm3(), cv, ptbuf, &len, ec_key);
	OPENSSL_assert(rv == 1);

	len = sizeof(ctbuf);
	rv = SM2_encrypt(EVP_sm3(), EVP_sm3(),
		SM2_DEFAULT_POINT_CONVERSION_FORM,
		(unsigned char *)msg, (size_t)strlen(msg), ctbuf, &len, ec_key);
	OPENSSL_assert(rv == 1);

	bzero(ptbuf, sizeof(ptbuf));
	len2 = sizeof(ptbuf);
	rv = SM2_decrypt(EVP_sm3(), EVP_sm3(),
		SM2_DEFAULT_POINT_CONVERSION_FORM,
		ctbuf, len, ptbuf, &len2, ec_key);
	OPENSSL_assert(rv == 1);

	/*
	printf("original  plaintext: %s\n", msg);
	printf("decrypted plaintext: %s\n", ptbuf);
	*/
	printf("%s() success\n", __FUNCTION__);
}

static void test_sm2_kap(void)
{
	int rv = 0;

	int curve_name = NID_sm2p256v1;
	EC_KEY *eckey1 = NULL;
	EC_KEY *eckey2 = NULL;
	SM2_KAP_CTX ctx1;
	SM2_KAP_CTX ctx2;

	eckey1 = EC_KEY_new_by_curve_name(curve_name);
	OPENSSL_assert(eckey1 != NULL);

	eckey2 = EC_KEY_new_by_curve_name(curve_name);
	OPENSSL_assert(eckey2 != NULL);

	rv = EC_KEY_generate_key(eckey1);
	OPENSSL_assert(rv == 1);

	rv = EC_KEY_generate_key(eckey2);
	OPENSSL_assert(rv == 1);

	rv = SM2_set_id(eckey1, "Alice");
	OPENSSL_assert(rv == 1);

	rv = SM2_set_id(eckey2, "Bob");
	OPENSSL_assert(rv == 1);


	rv = SM2_KAP_init();
	OPENSSL_assert(rv == 1);

	rv = SM2_KAP_prepare(&ctx1);
	OPENSSL_assert(rv == 1);

	rv = SM2_KAP_prepare(&ctx2);
	OPENSSL_assert(rv == 1);

	rv = SM2_KAP_compute_key(&ctx1);
	OPENSSL_assert(rv == 1);

	rv = SM2_KAP_compute_key(&ctx2);
	OPENSSL_assert(rv == 1);

	rv = SM2_KAP_final_check(&ctx1);
	OPENSSL_assert(rv == 1);
	
	rv = SM2_KAP_final_check(&ctx2);
	OPENSSL_assert(rv == 1);
}

int main(int argc, char **argv)
{
	int rv;
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_PKEY_METHOD *pmeth;
	const EVP_PKEY_ASN1_METHOD *ameth;
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	OPENSSL_assert(ec_key);

	rv = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(rv == 1);
		
	pkey = EVP_PKEY_new();
	OPENSSL_assert(pkey);

	pmeth = EVP_PKEY_meth_find(EVP_PKEY_SM2);
	OPENSSL_assert(pmeth);

	ameth = EVP_PKEY_asn1_find(NULL, EVP_PKEY_SM2);
	OPENSSL_assert(ameth);

	rv = EVP_PKEY_set1_SM2(pkey, ec_key);
	OPENSSL_assert(rv == 1);

	printf("pkey type    : %d\n", EVP_PKEY_type(pkey->type));
	printf("pkey id      : %d\n", EVP_PKEY_id(pkey));
	printf("pkey base id : %d\n", EVP_PKEY_base_id(pkey));
	printf("pkey bits    : %d\n", EVP_PKEY_bits(pkey));

	rv = EVP_PKEY_print_public(bio, pkey, 0, NULL);
	OPENSSL_assert(rv == 1);

	rv = EVP_PKEY_print_private(bio, pkey, 0, NULL);
	OPENSSL_assert(rv == 1);

	rv = EVP_PKEY_print_params(bio, pkey, 0, NULL);
	OPENSSL_assert(rv == 1);

	printf("%s() success!\n", __FUNCTION__);
	return 0;
}


int test_sm2_evp_digestsign(void)
{
	int rv;
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pk_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	const *EVP_MD *md = EVP_sm3();
	char *msg1 = "Hello ";
	char *msg2 = "World!";
	unsigned char sig[512];
	size_t siglen = sizeof(sig);


	/* init EVP_PKEY */

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	OPENSSL_assert(ec_key);

	rv = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(rv == 1);

	pkey = EVP_PKEY_new(); 
	OPENSSL_assert(pkey != NULL);

	rv = EVP_PKEY_set1_SM2(pkey, ec_key);
	OPENSSL_assert(rv == 1);

	/* test EVP_DigestSignInit/Update/Final */

	md_ctx = EVP_MD_CTX_create();
	OPENSSL_assert(md_ctx != NULL);

	rv = EVP_DigestSignInit(md_ctx, &pk_ctx, md, NULL, pkey);
	if (rv != 1)
		ERR_print_errors_fp(stderr);
	OPENSSL_assert(rv == 1);
	OPENSSL_assert(pkctx != NULL);

	rv = EVP_DigestSignUpdate(md_ctx, msg1, strlen(msg1));
	OPENSSL_assert(rv == 1);
	
	rv = EVP_DigestSignUpdate(md_ctx, msg2, strlen(msg2));
	OPENSSL_assert(rv == 1);

	rv = EVP_DigestSignFinal(md_ctx, sig, &siglen);
	OPENSSL_assert(rv == 1);

	EC_KEY_free(ec_key);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pk_ctx);
	EVP_MD_CTX_destroy(md_ctx);

	printf("%s() success!\n", __FUNCTION__);
	return 0;
}

int sm2_test_evp_pkey_encrypt(void)
{
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	char *msg = "Hello world!";
	unsigned char ptbuf[256];
	unsigned char ctbuf[256];
	size_t ptlen, ctlen, i;

	/* Generate SM2 EVP_PKEY */
	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	pkey = EVP_PKEY_new();
	EC_KEY_generate_key(ec_key);

	EVP_PKEY_set1_SM2(pkey, ec_key);

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	
	/* Encrypt */
	EVP_PKEY_encrypt_init(ctx);
	ctlen = sizeof(ctbuf);
	bzero(ctbuf, ctlen);
	EVP_PKEY_encrypt(ctx, ctbuf, &ctlen, (unsigned char *)msg, strlen(msg) + 1);
	
	printf("encrypted message (%zu bytes) : ", ctlen);
	for (i = 0; i < ctlen; i++) {
		printf("%02x", ctbuf[i]);
	}
	printf("\n");

	/* Decrypt */
	EVP_PKEY_decrypt_init(ctx);
	ptlen = sizeof(ptbuf);
	bzero(ptbuf, ptlen);
	if (!EVP_PKEY_decrypt(ctx, ptbuf, &ptlen, ctbuf, ctlen)) {
		fprintf(stderr, "sm2 decrypt failed.\n");
	}

	printf("decrypted message : %s\n", ptbuf);

	EVP_PKEY_free(pkey);
	EC_KEY_free(ec_key);
	EVP_PKEY_CTX_free(ctx);
	return 0;
}

EVP_PKEY *pkey_new_ec()
{
	int rv;
	ECIES_PARAMS param;
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	OPENSSL_assert(ec_key);
	rv = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(rv == 1);
	
	param.mac_nid = NID_hmac_full_ecies;
	param.kdf_md = EVP_sha1();
	param.sym_cipher = EVP_aes_128_cbc();
	param.mac_md = EVP_sha1();
	rv = ECIES_set_parameters(ec_key, &param);
	ERR_print_errors_fp(stderr);
	OPENSSL_assert(rv == 1);	
	OPENSSL_assert(ECIES_get_parameters(ec_key) != NULL);
	
	pkey = EVP_PKEY_new();
	OPENSSL_assert(pkey);

	const EVP_PKEY_ASN1_METHOD *ameth = EVP_PKEY_asn1_find(NULL, EVP_PKEY_SM2);
	OPENSSL_assert(ameth);

	rv = EVP_PKEY_set1_SM2(pkey, ec_key);
	ERR_print_errors_fp(stderr);
	OPENSSL_assert(rv == 1);

	return pkey;		
}

int test_sm2_pkey_seal(void)
{
	int rv;
	EVP_PKEY *pkey[2];
	int num_pkeys = sizeof(pkey)/sizeof(pkey[0]);
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher = EVP_sms4_cbc();
	unsigned char iv[16];
	unsigned char ek[2][256];
	int eklen[sizeof(pkey)/sizeof(pkey[0])];
	char *msg1 = "Hello ";
	char *msg2 = "World!";
	unsigned char ctbuf[256];
	unsigned char ptbuf[256];
	unsigned char *p;
	int len, ctlen;
	int i;

	for (i = 0; i < num_pkeys; i++) {
		pkey[i] = pkey_new_ec();
	}

	EVP_CIPHER_CTX_init(&ctx);

	RAND_bytes(iv, sizeof(iv));


	/* EVP_SealInit/Update/Final() */

	rv = EVP_SealInit(&ctx, cipher, ek, eklen, iv, pkey, num_pkeys);
	OPENSSL_assert(rv == num_pkeys);

	p = ctbuf;

	rv = EVP_SealUpdate(&ctx, p, &len, (unsigned char *)msg1, strlen(msg1));
	OPENSSL_assert(rv == 1);

	p += len;

	rv = EVP_SealUpdate(&ctx, p, &len, (unsigned char *)msg2, strlen(msg2));
	OPENSSL_assert(rv == 1);

	p += len;

	rv = EVP_SealFinal(&ctx, p, &len);
	OPENSSL_assert(rv == 1);

	p += len;

	ctlen = p - ctbuf;

	
	/* EVP_OpenInit/Update/Final() */	
	// TODO

	
	printf("%s() success!\n", __FUNCTION__);
	return 0;
}


int main(int argc, char **argv)
{
	test_sm2_sign();
	test_sm2_enc();
	return 0;
}


