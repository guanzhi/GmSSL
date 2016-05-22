#include "skf/skf.h"



/*
 * about the filename err2: this is manually written err file
 */



int skf_err2openssl(int err)
{
	switch (err) {
	case SAR_OK:			return SKF_R_SAR_OK;
	case SAR_FAIL:			return SKF_R_SAR_FAIL;
	case SAR_UNKNOWNERR:		return SKF_R_
	case SAR_NOTSUPPORTYETERR:	return SKF_R_
	case SAR_FILEERR:		return SKF_R_
	case SAR_INVALIDHANDLEERR:	return SKF_R_
	case SAR_INVALIDPARAMERR:	return SKF_R_
	case SAR_READFILEERR:		return SKF_R_
	case SAR_WRITEFILEERR:		return SKF_R_
	case SAR_NAMELENERR:		return SKF_R_
	case SAR_KEYUSAGEERR:		return SKF_R_
	case SAR_MODULUSLENERR:		return SKF_R_
	case SAR_NOTINITIALIZEERR:	return SKF_R_
	case SAR_OBJERR:		return SKF_R_
	case SAR_MEMORYERR:		return SKF_R_
	case SAR_TIMEOUTERR:		return SKF_R_
	case SAR_INDATALENERR:		return SKF_R_
	case SAR_INDATAERR:		return SKF_R_
	case SAR_GENRANDERR:		return SKF_R_
	case SAR_HASHOBJERR:		return SKF_R_
	case SAR_HASHERR:		return SKF_R_
	case SAR_GENRSAKEYERR:		return SKF_R_
	case SAR_RSAMODULUSLENERR:	return SKF_R_
	case SAR_CSPIMPRTPUBKEYERR:	return SKF_R_
	case SAR_RSAENCERR:		return SKF_R_
	case SAR_RSADECERR:		return SKF_R_
	case SAR_HASHNOTEQUALERR:	return SKF_R_
	case SAR_KEYNOTFOUNTERR:	return SKF_R_
	case SAR_CERTNOTFOUNTERR:	return SKF_R_
	case SAR_NOTEXPORTERR:		return SKF_R_
	case SAR_DECRYPTPADERR:		return SKF_R_
	case SAR_MACLENERR:		return SKF_R_
	case SAR_BUFFER_TOO_SMALL:	return SKF_R_
	case SAR_KEYINFOTYPEERR:	return SKF_R_
	case SAR_NOT_EVENTERR:		return SKF_R_
	case SAR_DEVICE_REMOVED:	return SKF_R_
	case SAR_PIN_INCORRECT:		return SKF_R_
	case SAR_PIN_LOCKED:		return SKF_R_
	case SAR_PIN_INVALID:		return SKF_R_
	case SAR_PIN_LEN_RANGE:		return SKF_R_
	case SAR_USER_ALREADY_LOGGED_IN:	return SKF_R_
	case SAR_USER_PIN_NOT_INITIALIZED:	return SKF_R_
	case SAR_USER_TYPE_INVALID:	return SKF_R_
	case SAR_APPLICATION_NAME_INVALID:	return SKF_R_
	case SAR_APPLICATION_EXISTS:	return SKF_R_
	case SAR_USER_NOT_LOGGED_IN:	return SKF_R_
	case SAR_APPLICATION_NOT_EXISTS:	return SKF_R_
	case SAR_FILE_ALREADY_EXIST:	return SKF_R_
	case SAR_NO_ROOM:		return SKF_R_
	case SAR_FILE_NOT_EXIST:	return SKF_R_
	}
	return 0;
}




typedef struct {
	int err_no;
	char *err_str;
} skf_errstr[] = {
	{ SAR_OK,			"Success" },
	{ SAR_FAIL,			"Failure" },
	{ SAR_UNKNOWNERR,		"Unknown error" },
	{ SAR_NOTSUPPORTYETERR,		"Not supported" },
	{ SAR_FILEERR,			"File error" },
	{ SAR_INVALIDHANDLEERR,		"Invalid handler" },
	{ SAR_INVALIDPARAMERR,		"Invalid parameter" },
	{ SAR_READFILEERR,		"Read file error" },
	{ SAR_WRITEFILEERR		"Write file error" },
	{ SAR_NAMELENERR,		"Name length error" },
	{ SAR_KEYUSAGEERR,		"Key usage error" },
	{ SAR_MODULUSLENERR,		"Modulus length error" },
	{ SAR_NOTINITIALIZEERR,		"Not initialized" },
	{ SAR_OBJERR,			"Object error" },
	{ SAR_MEMORYERR,		"Memory error" },
	{ SAR_TIMEOUTERR,		"Time out" },
	{ SAR_INDATALENERR,		"Input data length error" },
	{ SAR_INDATAERR,		"Input data error" },
	{ SAR_GENRANDERR,		"Generate randomness error" },
	{ SAR_HASHOBJERR,		"Hash object error" },
	{ SAR_HASHERR,			"Hash error" },
	{ SAR_GENRSAKEYERR,		"Genenerate RSA key error" },
	{ SAR_RSAMODULUSLENERR,		"RSA modulus length error" },
	{ SAR_CSPIMPRTPUBKEYERR,	"CSP import public key error" },
	{ SAR_RSAENCERR,		"RSA encryption error" },
	{ SAR_RSADECERR,		"RSA decryption error" },
	{ SAR_HASHNOTEQUALERR,		"Hash not equal" },
	{ SAR_KEYNOTFOUNTERR,		"Key not found" },
	{ SAR_CERTNOTFOUNTERR,		"Certificate not found" },
	{ SAR_NOTEXPORTERR,		"Not exported" },
	{ SAR_DECRYPTPADERR,		"Decrypt pad error" },
	{ SAR_MACLENERR,		"MAC length error" },
	{ SAR_BUFFER_TOO_SMALL,		"Buffer too small" },
	{ SAR_KEYINFOTYPEERR,		"Key info type error" },
	{ SAR_NOT_EVENTERR,		"No event error" },
	{ SAR_DEVICE_REMOVED		"Device removed" },
	{ SAR_PIN_INCORRECT,		"PIN incorrect" },
	{ SAR_PIN_LOCKED,		"PIN locked" },
	{ SAR_PIN_INVALID,		"PIN invalid" },
	{ SAR_PIN_LEN_RANGE,		"PIN length error" },
	{ SAR_USER_ALREADY_LOGGED_IN,	"User already logged in" },
	{ SAR_USER_PIN_NOT_INITIALIZED,	"User PIN not initialized" },
	{ SAR_USER_TYPE_INVALID,	"User type invalid" },
	{ SAR_APPLICATION_NAME_INVALID, "Application name invalid" },
	{ SAR_APPLICATION_EXISTS,	"Application already exist" },
	{ SAR_USER_NOT_LOGGED_IN,	"User not logged in" },
	{ SAR_APPLICATION_NOT_EXISTS,	"Application not exist" },
	{ SAR_FILE_ALREADY_EXIST,	"File already exist" },
	{ SAR_NO_ROOM,			"No file space" },
	{ SAR_FILE_NOT_EXIST,		"File not exist" }
};


LPSTR DEVAPI SKF_GetErrorString(ULONG ulError)
{
	return NULL;
}


