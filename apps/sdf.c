/* ====================================================================
 * Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.
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

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_SDF
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/pem.h>
# include <openssl/gmsdf.h>
# include <openssl/gmapi.h>
# include "apps.h"

typedef enum OPTION_choice {
	OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
	OPT_LIB, OPT_VENDOR, OPT_PRINTDEVINFO,
	OPT_PRINTSM2SIGN, OPT_PRINTSM2ENC,
	OPT_PRINTRSASIGN, OPT_PRINTRSAENC,
	OPT_ACCESSKEY, OPT_PASS,
	OPT_IMPORTOBJ, OPT_EXPORTOBJ, OPT_DELOBJ,
	OPT_IN, OPT_OUT
} OPTION_CHOICE;


# define OP_NONE		0
# define OP_PRINTDEVINFO	1
# define OP_PRINTSM2SIGN	2
# define OP_PRINTSM2ENC		3
# define OP_PRINTRSASIGN	4
# define OP_PRINTRSAENC		5
# define OP_ACCESSKEY		6
# define OP_IMPORTOBJ		7
# define OP_EXPORTOBJ 		8
# define OP_DELOBJ 		9

OPTIONS sdf_options[] = {
	{"help", OPT_HELP, '-', "Display this summary"},
	{"lib", OPT_LIB, 's', "Vendor's SDF dynamic library"},
	{"vendor", OPT_VENDOR, 's', "Vendor name"},
	{"printdevinfo", OPT_PRINTDEVINFO, '-', "Print device information"},
	{"printsm2sign", OPT_PRINTSM2SIGN, 's', "Print SM2 signing key with key index"},
	{"printsm2enc", OPT_PRINTSM2ENC, 's', "Print SM2 encryption key with key index"},
	{"printrsasign", OPT_PRINTRSASIGN, 's', "Print RSA signing key with key index"},
	{"printrsaenc", OPT_PRINTRSAENC, 's', "Print RSA encryption key with key index"},
	{"accesskey", OPT_ACCESSKEY, 's', "Access private key with the key index number"},
	{"pass", OPT_PASS, 's', "Passphrase source for accessing private key"},
	{"importobj", OPT_IMPORTOBJ, 's', "Import data object into device"},
	{"exportobj", OPT_EXPORTOBJ, 's', "Export data object from device"},
	{"delobj", OPT_DELOBJ, 's', "Delete data object from device"},
	{"in", OPT_IN, '<', "File to be imported from"},
	{"out", OPT_OUT, '>', "File to be exported to"},
	{NULL}
};

int sdf_main(int argc, char **argv)
{
	int ret = 1;
	char *infile = NULL, *outfile = NULL, *prog;
	char *objname = NULL, *passarg = NULL, *pass = NULL;
	BIO *in = NULL, *out = NULL;
	char *lib = NULL, *vendor = NULL;
	unsigned char *buf = NULL;
	unsigned int ulen;
	int len, key_idx = -1;
	OPTION_CHOICE o;
	int op = OP_NONE;
	void *hDev = NULL;
	void *hSession = NULL;

	prog = opt_init(argc, argv, sdf_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
opthelp:
			BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
			goto end;
		case OPT_HELP:
			opt_help(sdf_options);
			ret = 0;
			goto end;
		case OPT_LIB:
			lib = opt_arg();
			break;
		case OPT_VENDOR:
			vendor = opt_arg();
			break;
		case OPT_PRINTDEVINFO:
			if (op)
				goto opthelp;
			op = OP_PRINTDEVINFO;
			break;
		case OPT_PRINTSM2SIGN:
			if (op)
				goto opthelp;
			op = OP_PRINTSM2SIGN;
			key_idx = atoi(opt_arg());
			break;
		case OPT_PRINTSM2ENC:
			if (op)
				goto opthelp;
			op = OP_PRINTSM2ENC;
			key_idx = atoi(opt_arg());
			break;
		case OPT_PRINTRSASIGN:
			if (op)
				goto opthelp;
			op = OP_PRINTRSASIGN;
			key_idx = atoi(opt_arg());
			break;
		case OPT_PRINTRSAENC:
			if (op)
				goto opthelp;
			op = OP_PRINTRSAENC;
			key_idx = atoi(opt_arg());
			break;
		case OPT_ACCESSKEY:
			key_idx = atoi(opt_arg());
			break;
		case OPT_PASS:
			passarg = opt_arg();
			break;
		case OPT_IMPORTOBJ:
			if (op)
				goto opthelp;
			op = OP_IMPORTOBJ;
			objname = opt_arg();
			break;
		case OPT_EXPORTOBJ:
			if (op)
				goto opthelp;
			op = OP_EXPORTOBJ;
			objname = opt_arg();
			break;
		case OPT_DELOBJ:
			if (op)
				goto opthelp;
			op = OP_DELOBJ;
			objname = opt_arg();
			break;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUT:
			outfile = opt_arg();
			break;
		}
	}
	argc = opt_num_rest();
	if (argc != 0)
		goto opthelp;

	if (!lib) {
		BIO_printf(bio_err, "Option '-lib' required\n");
		goto opthelp;
	}
	if (SDF_LoadLibrary(lib, vendor) != SDR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	if (op == OP_NONE) {
		ret = 0;
		goto end;
	}

	if (SDF_OpenDevice(&hDev) != SDR_OK
		|| SDF_OpenSession(hDev, &hSession) != SDR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	switch (op) {
	case OP_PRINTDEVINFO:
	case OP_PRINTSM2SIGN:
	case OP_PRINTSM2ENC:
	case OP_PRINTRSASIGN:
	case OP_PRINTRSAENC:
		if (!(out = bio_open_default(outfile, 'w', FORMAT_TEXT))) {
			goto opthelp;
		}
		break;
	}

	switch (op) {
	case OP_PRINTSM2SIGN:
	case OP_PRINTSM2ENC:
	case OP_PRINTRSASIGN:
	case OP_PRINTRSAENC:
	case OP_ACCESSKEY:
		if (key_idx < SDF_MIN_KEY_INDEX || key_idx > SDF_MAX_KEY_INDEX) {
			BIO_printf(bio_err, "Invalid key index\n");
			goto end;
		}
		break;
	}

	if (op == OP_PRINTDEVINFO) {
		DEVICEINFO devInfo;
		if (SDF_GetDeviceInfo(hSession, &devInfo) != SDR_OK
			|| SDF_PrintDeviceInfo(out, &devInfo) != SDR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}

	} else if (op == OP_PRINTSM2SIGN || op == OP_PRINTSM2ENC) {
		ECCrefPublicKey publicKey;
		if (op == OP_PRINTSM2SIGN) {
			if (SDF_ExportSignPublicKey_ECC(hSession,
				key_idx, &publicKey) != SDR_OK) {
				ERR_print_errors(bio_err);
				goto end;
			}
			BIO_puts(out, "SM2 Signing Public Key:\n");
		} else {
			if (SDF_ExportEncPublicKey_ECC(hSession,
				key_idx, &publicKey) != SDR_OK) {
				ERR_print_errors(bio_err);
				goto end;
			}
			BIO_puts(out, "SM2 Encryption Public Key:\n");
		}
		if (SDF_PrintECCPublicKey(out, &publicKey) != SDR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}

	} else if (op == OP_PRINTRSASIGN || op == OP_PRINTRSAENC) {
		RSArefPublicKey publicKey;
		if (op == OP_PRINTRSASIGN) {
			if (SDF_ExportSignPublicKey_RSA(hSession,
				key_idx, &publicKey) != SDR_OK) {
				ERR_print_errors(bio_err);
				goto end;
			}
			BIO_puts(out, "RSA Signing Public Key:\n");
		} else {
			if (SDF_ExportEncPublicKey_RSA(hSession,
				key_idx, &publicKey) != SDR_OK) {
				ERR_print_errors(bio_err);
				goto end;
			}
			BIO_puts(out, "RSA Encryption Public Key:\n");
		}
		if (SDF_PrintRSAPublicKey(out, &publicKey) != SDR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}

	} else if (op == OP_ACCESSKEY) {
		if (!app_passwd(passarg, NULL, &pass, NULL)) {
			BIO_printf(bio_err, "Error getting password\n");
			goto end;
		}
		if (SDF_GetPrivateKeyAccessRight(hSession, (unsigned int)key_idx,
			(unsigned char *)pass, strlen(pass)) != SDR_OK) {
			OPENSSL_cleanse(pass, sizeof(pass));
			return 0;
		}
		(void)SDF_ReleasePrivateKeyAccessRight(hSession, (unsigned int)key_idx);
		BIO_printf(bio_err, "Access private key %d success\n", key_idx);

	} else if (op == OP_IMPORTOBJ) {
		if (!(in = bio_open_default(infile, 'r', FORMAT_BINARY))) {
			goto opthelp;
		}
		if ((len = bio_to_mem(&buf, SDF_MAX_FILE_SIZE, in)) < 0) {
			BIO_printf(bio_err, "Error reading data object content\n");
			goto end;
		}
		if (SDF_CreateFile(hSession, (unsigned char *)objname, strlen(objname), len) != SDR_OK
			|| SDF_WriteFile(hSession, (unsigned char *)objname, strlen(objname), 0, len, buf) != SDR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}
		BIO_printf(bio_err, "Object '%s' (%d bytes) created\n", objname, len);

	} else if (op == OP_EXPORTOBJ) {
		if (!(out = bio_open_default(outfile, 'w', FORMAT_BINARY))) {
			goto opthelp;
		}
		if (!(buf = OPENSSL_zalloc(SDF_MAX_FILE_SIZE))
			|| SDF_ReadFile(hSession, (unsigned char *)objname, strlen(objname), 0, &ulen, buf) != SDR_OK
			|| BIO_write(out, buf, ulen) != ulen) {
			ERR_print_errors(bio_err);
			goto end;
		}
		BIO_printf(bio_err, "Object '%s' (%u bytes) exported\n", objname, ulen);

	} else if (op == OP_DELOBJ) {
		if (SDF_DeleteFile(hSession, (unsigned char *)objname, strlen(objname)) != SDR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}
		BIO_printf(bio_err, "Object '%s' deleted\n", objname);

	} else {
		goto end;
	}

	ret = 0;

end:
	BIO_free(in);
	BIO_free(out);
	OPENSSL_free(buf);
	OPENSSL_free(pass);
	if (hSession) (void)SDF_CloseSession(hSession);
	if (hDev) (void)SDF_CloseDevice(hDev);
	if (lib) SDF_UnloadLibrary();
	return ret;
}
#endif
