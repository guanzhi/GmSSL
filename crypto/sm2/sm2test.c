#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include "sm2.h"
#include "sm3.h"

void  SM2PKE_test3()
{
	/* test3 params */
	const char *p = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
	const char *a = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
	const char *b = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
	const char *xG = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
	const char *yG = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
	const char *n = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
	const char *dB = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
	const char *xB = "435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A";
	const char *yB = "75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42";
	
	BIGNUM *bn_p = BN_new();
	BN_hex2bn(&bn_p, p);
	BIGNUM *bn_a = BN_new();
	BN_hex2bn(&bn_a, a);
	BIGNUM *bn_b = BN_new();
	BN_hex2bn(&bn_b, b);
	BIGNUM *bn_xG = BN_new();
	BN_hex2bn(&bn_xG, xG);
	BIGNUM *bn_yG = BN_new();
	BN_hex2bn(&bn_yG, yG);
	BIGNUM *bn_n = BN_new();
	BN_hex2bn(&bn_n, n);
	BIGNUM *bn_dB = BN_new();
	BN_hex2bn(&bn_dB, dB);
	BIGNUM *bn_xB = BN_new();
	BN_hex2bn(&bn_xB, xB);
	BIGNUM *bn_yB = BN_new();
	BN_hex2bn(&bn_yB, yB);
	
	BN_CTX *bn_ctx = BN_CTX_new();
	EC_GROUP *ec_group = EC_GROUP_new(EC_GFp_mont_method());
	EC_GROUP_set_curve_GFp(ec_group, bn_p, bn_a, bn_b, bn_ctx);

	EC_POINT *G = EC_POINT_new(ec_group);
	EC_POINT_set_affine_coordinates_GFp(ec_group, G, bn_xG, bn_yG, bn_ctx);
	BIGNUM *bn_h = BN_new();	/* cofactor h = #E(Fp) / n */
	BN_div(bn_h, NULL, bn_p, bn_n, bn_ctx);
	EC_GROUP_set_generator(ec_group, G, bn_n, bn_h);
	
	EC_POINT *PB = EC_POINT_new(ec_group);
	EC_POINT_set_affine_coordinates_GFp(ec_group, PB, bn_xB, bn_yB, bn_ctx);
	EC_KEY *ec_key_B = EC_KEY_new();
	EC_KEY_set_group(ec_key_B, ec_group);
	EC_KEY_set_private_key(ec_key_B, bn_dB);
	EC_KEY_set_public_key(ec_key_B, PB);
	
	BN_free(bn_p);
	BN_free(bn_a);
	BN_free(bn_b);
	BN_free(bn_n);
	BN_free(bn_xG);
	BN_free(bn_yG);
	BN_free(bn_dB);
	BN_free(bn_xB);
	BN_free(bn_yB);
	BN_free(bn_h);
	BN_CTX_free(bn_ctx);
	EC_POINT_free(G);
	EC_POINT_free(PB);
	EC_GROUP_free(ec_group);

	char *M = "encryption standard";
	char *ctest = "04245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252"
	"E776CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01"
	"B8650053A89B41C418B0C3AAD00D886C002864679C3D7360C30156FAB7C80A02"
	"76712DA9D8094A634B766D3A285E07480653426D";
	BIGNUM *ct = BN_new();
	BN_hex2bn(&ct, ctest);
	unsigned char ct2bin[116];
	BN_bn2bin(ct, ct2bin);
	BN_free(ct);

	int mlen = strlen(M);
	int c1len = PRIME_SIZE / 8 * 2 + 1;
	int clen = c1len + mlen + HASH_V / 8;
	
	unsigned char *C = malloc(sizeof(unsigned char) * clen);
	sm2_pke_encrypt(C, M, mlen, ec_key_B);	
	if (memcmp(C, ct2bin, clen) == 0)
		printf("sm2_pke_encrypt passed.\n");
	else 
		printf("sm2_pke_encrypt failed.\n");
	free(C);
	
	int m1len = clen - c1len - HASH_V / 8;
	unsigned char *M1bin = malloc(sizeof(unsigned char) * m1len);
	sm2_pke_decrypt((char *)ct2bin, M1bin, m1len, ec_key_B);	
	if (memcmp(M1bin, M, m1len) == 0)
		printf("sm2_pke_decrypt passed.\n");
	else 
		printf("sm2_pke_decrypt failed.\n");
	free(M1bin);

	EC_KEY_free(ec_key_B);
}

int main()
{
	SM2PKE_test3();
	return 0;
}

