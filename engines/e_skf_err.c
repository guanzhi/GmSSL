#include "smapi_err.h"

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

typedef struct {
	uint32_t alg_id;
	char *alg_name;
} smapi_algid[] = {
	{ SGD_RSA,			"RSA" },
	{ SGD_RSA | SGD_SHA1,		"RSA-with-SHA1" },
};

LPSTR DEVAPI SKF_GetErrorString(ULONG ulError)
{
	/*
	 * TODO: check smapi_errstr[] and return the error string
	 * if error number not exist, return NULL;
	 */
	return NULL;
}

LPSTR DEVAPI SKF_GetAlgorString(ULONG ulAlgId)
{
	return NULL;
}
