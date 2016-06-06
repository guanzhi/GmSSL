/* crypto/skf/skf_errstr.c */
/* ====================================================================
 * Copyright (c) 2014 - 2016 The GmSSL Project.  All rights reserved.
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
 *
 */

#include <openssl/skf.h>

typedef struct {
	int err_no;
	char *err_str;
} skf_errinfo;


skf_errinfo skf_errstr[] = {
	{ SAR_OK,			"Success" },
	{ SAR_FAIL,			"Failure" },
	{ SAR_UNKNOWNERR,		"Unknown error" },
	{ SAR_NOTSUPPORTYETERR,		"Not supported" },
	{ SAR_FILEERR,			"File error" },
	{ SAR_INVALIDHANDLEERR,		"Invalid handle" },
	{ SAR_INVALIDPARAMERR,		"Invalid parameter" },
	{ SAR_READFILEERR,		"Read file error" },
	{ SAR_WRITEFILEERR,		"Write file error" },
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
	{ SAR_DEVICE_REMOVED,		"Device removed" },
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

char *SKF_get_errstr(ULONG ulError)
{
	int i;
	for (i = 0; i < sizeof(skf_errstr)/sizeof(skf_errstr[0]); i++) {
		if (ulError == skf_errstr[i].err_no) {
			return skf_errstr[i].err_str;
		}
	}
	return "(undef)";
}



