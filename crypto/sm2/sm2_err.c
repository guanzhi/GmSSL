#include <stdio.h>
#include <openssl/err.h>
#include "sm2.h"

#ifndef OPENSSL_NO_ERR

#define ERR_FUNC(func) ERR_PACK(ERR_LIB_ECIES,func,0)
#define ERR_REASON(reason) ERR_PACK(ERR_LIB_ECIES,0,reason)


static ERR_STRING_DATA SM2_str_functs[] = {
	{ERR_FUNC(ECIES_F_ECIES_DO_ENCRYPT),	"ECIES_do_encrypt"},
	{ERR_FUNC(ECIES_F_ECIES_DO_DECRYPT),	"ECIES_do_decrypt"},
	{0,NULL}
};

static ERR_STRING_DATA SM2_str_reasons[] = {
	{ERR_REASON(ECIES_R_BAD_DATA),		"bad data"},
	{ERR_REASON(ECIES_R_UNKNOWN_CIPHER_TYPE),"unknown cipher type"},
	{ERR_REASON(ECIES_R_ENCRYPT_FAILED),	"encrypt failed"},
	{ERR_REASON(ECIES_R_DECRYPT_FAILED),	"decrypt failed"},
	{ERR_REASON(ECIES_R_UNKNOWN_MAC_TYPE),	"unknown MAC type"},
	{ERR_REASON(ECIES_R_GEN_MAC_FAILED),	"MAC generation failed"},
	{ERR_REASON(ECIES_R_VERIFY_MAC_FAILED),	"MAC verification failed"},
	{ERR_REASON(ECIES_R_ECDH_FAILED),	"ECDH failed"},
	{ERR_REASON(ECIES_R_BUFFER_TOO_SMALL),	"buffer too small"},
	{0,NULL}
};

#endif

void ERR_load_ECIES_strings(void)
{
#ifndef OPENSSL_NO_ERR

	if (ERR_func_error_string(ECIES_str_functs[0].error) == NULL) {
		ERR_load_strings(0,ECIES_str_functs);
		ERR_load_strings(0,ECIES_str_reasons);
	}
#endif
}
