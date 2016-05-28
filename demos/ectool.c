/*
 * ecc - elliptic curve cryptography toolkit
 * a command line tool perform basic ecc cryptography
 * include ecpoint add, double, scalar multiply, invert
 * ecdsa sign and verify
 * ec -sign  -key a.file -pass 123456
 * ec -verify <signature> -key a.file 
 */





#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <popt.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>

enum commands {
	ECC_PRINT = 1,
	ECC_CHECK_POINT,
	ECC_RAND_SKEY,
	ECC_RAND_KEYPAIR,
	ECC_ADD,
	ECC_DOUBLE,
	ECC_MUL,
	ECC_MUL_G,
	ECC_INVERT,
	ECC_SIGN,
	ECC_VERIFY,
};

int main(int argc, const char *argv[])
{
	int r;
	int ok = 0;
	char *prog = "ecc";

	
	// libpopt var
	poptContext popt_ctx;
	const char **rest;
	int command = 0;
	char *curve_name = "secp192k1";
	int point_compressed = 0;
	point_conversion_form_t point_form;

	struct poptOption options[] = {
		{"curve-name",		'c', POPT_ARG_STRING, &curve_name, 0,		"elliptic curve name", "NAME"},
		{"point-compressed",	'z', POPT_ARG_NONE, &point_compressed, 0,	"point format, compress or uncompress", NULL},
		{"print-curve",		'p', POPT_ARG_VAL, &command, ECC_PRINT,		"print elliptic curve parameters", NULL},
		{"random-private-key",	 0,  POPT_ARG_VAL, &command, ECC_RAND_SKEY,	"random generate a private key\n", NULL},
		{"random-keypair",	 0,  POPT_ARG_VAL, &command, ECC_RAND_KEYPAIR,	"generate a random key pair\n", NULL},
		{"check-point",		'e', POPT_ARG_VAL, &command, ECC_CHECK_POINT,	"check if point is valid\n", NULL},
		{"point-add",		'a', POPT_ARG_VAL, &command, ECC_ADD,		"elliptic curve point addition", NULL},
		{"point-double",	'b', POPT_ARG_VAL, &command, ECC_DOUBLE,	"elliptic curve point double", NULL},
		{"point-mul",		'x', POPT_ARG_VAL, &command, ECC_MUL,		"k*G", NULL},
		{"point-mul-generator",	'X', POPT_ARG_VAL, &command, ECC_MUL_G,		"elliptic curve point scalar multiply", NULL},
		{"point-invert",	'i', POPT_ARG_VAL, &command, ECC_INVERT,	"elliptic curve point inverse", NULL},
		{"ecdsa-sign",		's', POPT_ARG_VAL, &command, ECC_SIGN,		"ecdsa sign", NULL},
		{"ecdsa-verify",	'v', POPT_ARG_VAL, &command, ECC_VERIFY,	"ecdsa verify", NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	// openssl var
	EC_GROUP *ec_group = NULL;
	EC_POINT *P = NULL;
	EC_POINT *Q = NULL;
	EC_POINT *R = NULL;
	BIGNUM *k = BN_new();
	BN_CTX *bn_ctx = BN_CTX_new();


	// argument parsing
	popt_ctx = poptGetContext(argv[0], argc, argv, options, 0);
	if ((r = poptGetNextOpt(popt_ctx)) < -1) {
		fprintf(stderr, "%s: bad argument %s: %s\n", argv[0], 
			poptBadOption(popt_ctx, POPT_BADOPTION_NOALIAS), 
			poptStrerror(r));
		goto exit;
	}
	rest = poptGetArgs(popt_ctx);


	// check arguments
	ec_group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(curve_name));
	if (ec_group == NULL) {
		fprintf(stderr, "%s: unknown curve name\n", prog);
		goto exit;
	}

	P = EC_POINT_new(ec_group);
	Q = EC_POINT_new(ec_group);
	R = EC_POINT_new(ec_group);

	point_form = point_compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;

	switch (command) {
	case ECC_PRINT:
		{
		BIGNUM *p = BN_new();
		BIGNUM *a = BN_new();
		BIGNUM *b = BN_new();
		char *generator;
		BIGNUM *order = BN_new();
		BIGNUM *cofactor = BN_new();

		EC_GROUP_get_curve_GFp(ec_group, p, a, b, bn_ctx);
		generator = EC_POINT_point2hex(ec_group, EC_GROUP_get0_generator(ec_group), point_form, bn_ctx);
		EC_GROUP_get_order(ec_group, order, bn_ctx);
		EC_GROUP_get_cofactor(ec_group, cofactor, bn_ctx);
		
		fprintf(stdout, "Name      : %s\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ec_group)));
		fprintf(stdout, "FieldType : %s\n", "PrimeField");
		fprintf(stdout, "Prime     : %s\n", BN_bn2hex(p));
		fprintf(stdout, "A         : %s\n", BN_bn2hex(a));
		fprintf(stdout, "B         : %s\n", BN_bn2hex(b));
		fprintf(stdout, "Generator : %s\n", generator);
		fprintf(stdout, "Order     : %s\n", BN_bn2hex(order));
		fprintf(stdout, "Cofactor  : %s\n", BN_bn2hex(cofactor));

		BN_free(p);
		BN_free(a);
		BN_free(b);
		BN_free(order);
		BN_free(cofactor);

		break;
		}
	case ECC_CHECK_POINT:
		{
		if (!rest) {
			fprintf(stderr, "%s: short of point\n", prog);
			goto exit;
		}
		if (!rest[0]) {
			fprintf(stderr, "%s: short of point\n", prog);
			goto exit;
		}
		if (EC_POINT_hex2point(ec_group, rest[0], P, bn_ctx))
			fprintf(stdout, "ture\n");
		else
			fprintf(stdout, "false\n");
		break;
		}
	case ECC_RAND_SKEY:
		{
		EC_KEY *ec_key = EC_KEY_new();
		EC_KEY_set_group(ec_key, ec_group);
		EC_KEY_generate_key(ec_key);
		fprintf(stdout, "%s\n", BN_bn2hex(EC_KEY_get0_private_key(ec_key)));
		EC_KEY_free(ec_key);
		break;
		}
	case ECC_RAND_KEYPAIR:
		{
		EC_KEY *ec_key = EC_KEY_new();
		EC_KEY_set_group(ec_key, ec_group);
		EC_KEY_generate_key(ec_key);
		fprintf(stdout, "%s\n", BN_bn2hex(EC_KEY_get0_private_key(ec_key)));
		fprintf(stdout, "%s\n", EC_POINT_point2hex(ec_group, EC_KEY_get0_public_key(ec_key), point_form, bn_ctx));
		EC_KEY_free(ec_key);
		break;
		}
	case ECC_ADD:
		{
		if (!rest) {
			fprintf(stderr, "%s: short of point\n", prog);
			goto exit;
		}
		if (!rest[0] || !rest[1]) {
			fprintf(stderr, "%s: short of point\n", prog);
			goto exit;
		}			
		if (!EC_POINT_hex2point(ec_group, rest[1], P, bn_ctx)) {
			fprintf(stderr, "%s: first point invalid\n", prog);
			goto exit;
		}
		if (!EC_POINT_hex2point(ec_group, rest[1], Q, bn_ctx)) {
			fprintf(stderr, "%s: second point invalid\n", prog);
			goto exit;
		}
		EC_POINT_add(ec_group, R, P, Q, bn_ctx);
		fprintf(stdout, "%s\n", EC_POINT_point2hex(ec_group, R, point_form, bn_ctx));
		break;
		}
	case ECC_DOUBLE:
		{
		EC_POINT_dbl(ec_group, R, P, bn_ctx);
		fprintf(stdout, "%s\n", EC_POINT_point2hex(ec_group, R, point_form, bn_ctx));
		break;
		}
	case ECC_MUL:
		{
		BIGNUM *order = NULL;

		if (!BN_hex2bn(&k, rest[0])) {
			fprintf(stderr, "%s: integer invalid\n", prog);
			goto exit;
		}
		
		order = BN_new();
		EC_GROUP_get_order(ec_group, order, bn_ctx);
		if (BN_cmp(k, order) >= 0) {
			fprintf(stderr, "%s: integer value invalid\n", prog);
			BN_free(order);
			goto exit;
		}
		BN_free(order);

		if (!EC_POINT_hex2point(ec_group, rest[1], P, bn_ctx)) {
			fprintf(stderr, "%s: point invalid\n", prog);
			goto exit;
		}

		EC_POINT_mul(ec_group, R, k, P, NULL, bn_ctx);
		fprintf(stdout, "%s\n", EC_POINT_point2hex(ec_group, R, point_form, bn_ctx));

		break;
		}
	case ECC_MUL_G:
		{
		BIGNUM *order = NULL;
		if (!BN_hex2bn(&k, rest[0])) {
			fprintf(stderr, "%s: integer format invalid\n", prog);
			goto exit;
		}
		
		order = BN_new();
		EC_GROUP_get_order(ec_group, order, bn_ctx);
		if (BN_cmp(k, order) >= 0) {
			fprintf(stderr, "%s: integer value invalid\n", prog);
			BN_free(order);
			goto exit;
		}
		BN_free(order);
		
		EC_POINT_mul(ec_group, R, k, EC_GROUP_get0_generator(ec_group), NULL, bn_ctx);
		fprintf(stdout, "%s\n", EC_POINT_point2hex(ec_group, R, point_form, bn_ctx));
		break;
		}
	default:
		fprintf(stderr, "%s: command is required\n", prog);
		break;
	}
	ok = 1;

exit:
	if (ec_group) EC_GROUP_free(ec_group);
	if (P) EC_POINT_free(P);
	if (k) BN_free(k);
	if (bn_ctx) BN_CTX_free(bn_ctx);

	return ok ? 0 : -1;
}
