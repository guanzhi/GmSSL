#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/cbcmac.h>
#include "../modes/modes_lcl.h"
#include <openssl/otp.h>

static int pow_table[] = {
	1,
	10,
	100,
	1000,
	10000,
	100000,
	1000000,
	10000000,
	100000000,
};

static int check_params(const OTP_PARAMS *params)
{
	if ((params->te < 1 || params->te > 60) ||
		(params->type != NID_sm3 && params->type != NID_sms4_ecb) || /* about to change */
		(params->otp_digits >= sizeof(pow_table) || params->otp_digits < 4)) {
		return 0;
	}
	return 1;
}

int OTP_generate(const OTP_PARAMS *params, const void *event, size_t eventlen,
	unsigned int *otp, const unsigned char *key, size_t keylen)
{
	int ret = 0;
	time_t t = 0;
	unsigned char *id = NULL;
	size_t idlen;
	const EVP_MD *md;
	const EVP_CIPHER *cipher;
	EVP_MD_CTX *mdctx = NULL;
	CBCMAC_CTX *cmctx = NULL;
	unsigned char s[EVP_MAX_MD_SIZE];
	size_t slen;
	uint32_t od;
	int i, n;

	OPENSSL_assert(sizeof(time_t) == 8);

	if (!check_params(params)) {
		OTPerr(OTP_F_OTP_GENERATE, OTP_R_INVALID_PARAMS);
		return 0;
	}

	idlen = sizeof(uint64_t) + eventlen + params->option_size;
	if (idlen < 16) {
		idlen = 16;
	}
	if (!(id = OPENSSL_malloc(idlen))) {
		OTPerr(OTP_F_OTP_GENERATE, OTP_R_MALLOC_FAILED);
		goto end;
	}
	memset(id, 0, idlen);

	t = time(NULL) + params->offset;
	t /= params->te;

	memcpy(id, &t, sizeof(t));
	memcpy(id + sizeof(t), event, eventlen);
	memcpy(id + sizeof(t) + eventlen, params->option, params->option_size);


	/* FIXME: try to get md and cipher, and check if cipher is ECB */
	if (params->type == NID_sm3) {
		md = EVP_get_digestbynid(params->type);
		if (!(mdctx = EVP_MD_CTX_create())) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_EVP_LIB);
			goto end;
		}
		if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_EVP_LIB);
			goto end;
		}
		if (!EVP_DigestUpdate(mdctx, key, keylen)) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_EVP_LIB);
			goto end;
		}
		if (!EVP_DigestUpdate(mdctx, id, idlen)) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_EVP_LIB);
			goto end;
		}
		if (!EVP_DigestFinal_ex(mdctx, s, (unsigned int *)&slen)) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_EVP_LIB);
			goto end;
		}
	} else if (params->type == NID_sms4_ecb) {
		cipher = EVP_get_cipherbynid(params->type);
		if (!(cmctx = CBCMAC_CTX_new())) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_CBCMAC_LIB);
			goto end;
		}
		if (!CBCMAC_Init(cmctx, key, keylen, cipher, NULL)) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_CBCMAC_LIB);
			goto end;
		}
		if (!CBCMAC_Update(cmctx, id, idlen)) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_CBCMAC_LIB);
			goto end;
		}
		if (!CBCMAC_Final(cmctx, s, &slen)) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_CBCMAC_LIB);
			goto end;
		}
	} else {
		goto end;
	}
	OPENSSL_assert(slen % 4 == 0);

	od = 0;

	n = (int)slen;
	for (i = 0; i < n/4; i++) {
		od += GETU32(&s[i * 4]);
	}

	*otp = od % pow_table[params->otp_digits];
	ret = 1;
end:
	OPENSSL_free(id);
	EVP_MD_CTX_destroy(mdctx);
	CBCMAC_CTX_free(cmctx);
	return ret;
}

