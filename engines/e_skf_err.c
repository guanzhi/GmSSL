#include "skf/skf.h"







static ERR_STRING_DATA SKF_str_functs[] = {
	{ERR_FUNC(SKF_F_SKF_INIT_KEY), "SKF_INIT_KEY"},
	{ERR_FUNC(SKF_F_SKF_CIPHER), "SKF_CIPHER"},
	{ERR_FUNC(SKF_F_SKF_INIT), "SKF_INIT"},
	{ERR_FUNC(SKF_F_SKF_CTRL), "SKF_CTRL"},
	{ERR_FUNC(SKF_F_SKF_FINISH), "SKF_FINISH"},
	{0, NULL}
};

static ERR_STRING_DATA SKF_str_reasons[] = {
	{ERR_REASON(SKF_F_OK),	ok"},
	{0, NULL}
};


int skf_err2openssl(int err)
{
	switch (err) {
	case SAR_OK:
		return SKF_R_SAR_OK;
	case SAR_FAIL:
		return SKF_R_SAR_FAIL;
	case SAR_UNKNOWNERR:
	case SAR_NOTSUPPORTYETERR:
	case SAR_FILEERR:
	case SAR_INVALIDHANDLEERR:
	case SAR_INVALIDPARAMERR:
	case SAR_READFILEERR:
	case SAR_WRITEFILEERR:
	case SAR_NAMELENERR:
	case SAR_KEYUSAGEERR:
	case SAR_MODULUSLENERR:
	case SAR_NOTINITIALIZEERR:
	case SAR_OBJERR:
	case SAR_MEMORYERR:
	case SAR_TIMEOUTERR:
	case SAR_INDATALENERR
	case SAR_INDATAERR
	case SAR_GENRANDERR
	case SAR_HASHOBJERR
	case SAR_HASHERR
	case SAR_GENRSAKEYERR
	case SAR_RSAMODULUSLENERR
	case SAR_CSPIMPRTPUBKEYERR
	case SAR_RSAENCERR
	case SAR_RSADECERR
	case SAR_HASHNOTEQUALERR
	case SAR_KEYNOTFOUNTERR
	case SAR_CERTNOTFOUNTERR
	case SAR_NOTEXPORTERR
	case SAR_DECRYPTPADERR
	case SAR_MACLENERR
	case SAR_BUFFER_TOO_SMALL
	case SAR_KEYINFOTYPEERR
	case SAR_NOT_EVENTERR
	case SAR_DEVICE_REMOVED
	case SAR_PIN_INCORRECT
	case SAR_PIN_LOCKED
	case SAR_PIN_INVALID
	case SAR_PIN_LEN_RANGE
	case SAR_USER_ALREADY_LOGGED_IN
	case SAR_USER_PIN_NOT_INITIALIZED
	case SAR_USER_TYPE_INVALID
	case SAR_APPLICATION_NAME_INVALID
	case SAR_APPLICATION_EXISTS
	case SAR_USER_NOT_LOGGED_IN
	case SAR_APPLICATION_NOT_EXISTS
	case SAR_FILE_ALREADY_EXIST
	case SAR_NO_ROOM
	case SAR_FILE_NOT_EXIST
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


