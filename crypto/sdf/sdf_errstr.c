/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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
 */

#include <openssl/err.h>
#include <openssl/sdf.h>
#include "../../e_os.h"

static ERR_STRING_DATA sdf_errstr[] = {
	{ SDR_OK,		"Success" },
	{ SDR_BASE,		"Base" },
	{ SDR_UNKNOWERR,	"Unknown error" },
	{ SDR_NOTSUPPORT,	"Not supported" },
	{ SDR_COMMFAIL,		"Commnunication failure" },
	{ SDR_HARDFAIL,		"Hardware failure" },
	{ SDR_OPENDEVICE,	"Open device" },
	{ SDR_OPENSESSION,	"Open session" },
	{ SDR_PARDENY,		"Private key access denied (for index 0)" },
	{ SDR_KEYNOTEXIST,	"Key not exist" },
	{ SDR_ALGNOTSUPPOT,	"Algorithm not supported" },
	{ SDR_ALGMODNOTSUPPORT,	"Algorithm mode not supported" },
	{ SDR_PKOPERR,		"Public key operation error" },
	{ SDR_SKOPERR,		"Private key operation error" },
	{ SDR_SIGNERR,		"Signature generation error" },
	{ SDR_VERIFYERR,	"Singature verification error" },
	{ SDR_SYMOPERR,		"Symmetric encryption error" },
	{ SDR_STEPERR,		"Multi-step operation error" },
	{ SDR_FILESIZEERR,	"File size error" },
	{ SDR_FILENOEXIST,	"File not exist" },
	{ SDR_FILEOFSERR,	"File offset error" },
	{ SDR_KEYTYPEERR,	"Key type error" },
	{ SDR_KEYERR,		"Key error" },
	{ SDR_ENCDATAERR,	"ECC encrypted data error" },
	{ SDR_RANDERR,		"Random number generator error" },
	{ SDR_PRKRERR,		"Private key privilege error" },
	{ SDR_MACERR,		"MAC computation error" },
	{ SDR_FILEEXSITS,	"File already exist" },
	{ SDR_FILEWERR,		"File write error" },
	{ SDR_NOBUFFER,		"No buffer" },
	{ SDR_INARGERR,		"Input argument error" },
	{ SDR_OUTARGERR,	"Output argument error" },
};

const char *SDF_GetErrorString(int err)
{
	int i;
	for (i = 0; i < OSSL_NELEM(sdf_errstr); i++) {
		if (err == sdf_errstr[i].error) {
			return sdf_errstr[i].string;
		}
	}
	return "(undef)";
}

