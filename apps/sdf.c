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
	OPT_SO_PATH, OPT_DEVINFO, OPT_KEY, OPT_PASS,
	OPT_IMPORT, OPT_EXPORT, OPT_DELETE, OPT_LABEL,
	OPT_IN, OPT_OUT
} OPTION_CHOICE;

# define FILE_OP_NONE	0
# define FILE_OP_IMPORT	1
# define FILE_OP_EXPORT 2
# define FILE_OP_DELETE 3

# define DEFAULT_SO_PATH	"libsdf.so"

OPTIONS sdf_options[] = {
	{"help", OPT_HELP, '-', "Display this summary"},
	{"so_path", OPT_SO_PATH, 's', "Vendor's dynamic library"},
	{"devinfo", OPT_DEVINFO, '-', "Print device information"},
	{"key", OPT_KEY, 's', "Access private key with the key index"},
	{"pass", OPT_PASS, 's', "Passphrase source"},
	{"import", OPT_IMPORT, '-', "Import data object into device"},
	{"export", OPT_EXPORT, '-', "Export data object from device"},
	{"delete", OPT_DELETE, '-', "Delete data object from device"},
	{"label", OPT_LABEL, 's', "Data object label"},
	{"in", OPT_IN, '<', "File to be imported from"},
	{"out", OPT_OUT, '>', "File to be exported to"},
	{NULL}
};

int sdf_main(int argc, char **argv)
{
	int ret = 1;
	char *infile = NULL, *outfile = NULL, *prog;
	char *label = NULL, *passarg = NULL, *pass = NULL;
	BIO *in = NULL, *out = NULL;
	OPTION_CHOICE o;
	char *so_path = NULL;
	int print_devinfo = 0;
	int key_idx = -1;
	int file_op = FILE_OP_NONE;
	void *hDev = NULL;
	void *hSession = NULL;
	unsigned char *buf = NULL;
	int len = 0;
	int rv;
	unsigned int ulen;

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
		case OPT_SO_PATH:
			so_path = opt_arg();
			break;
		case OPT_DEVINFO:
			print_devinfo = 1;
			break;
		case OPT_IMPORT:
			if (file_op)
				goto opthelp;
			file_op = FILE_OP_IMPORT;
			break;
		case OPT_EXPORT:
			if (file_op)
				goto opthelp;
			file_op = FILE_OP_EXPORT;
			break;
		case OPT_DELETE:
			if (file_op)
				goto opthelp;
			file_op = FILE_OP_DELETE;
			break;
		case OPT_LABEL:
			label = opt_arg();
			break;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUT:
			outfile = opt_arg();
			break;
		case OPT_PASS:
			passarg = opt_arg();
			break;
		case OPT_KEY:
			if ((key_idx = atoi(opt_arg())) < 0) {
				BIO_printf(bio_err, "Invalid key index\n");
				goto end;
			}
			break;
		}
	}
	argc = opt_num_rest();
	if (argc != 0)
		goto opthelp;

	if (!so_path) {
		BIO_printf(bio_err, "Vendor's SDF dynmaic library required\n");
		goto opthelp;
	}
	if (SDF_LoadLibrary(so_path, NULL) != SDR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	/* no operation specified */
	if (!print_devinfo && key_idx < 0 && !file_op) {
		goto end;
	}

	if (SDF_OpenDevice(&hDev) != SDR_OK
		|| SDF_OpenSession(hDev, &hSession) != SDR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	if (print_devinfo) {
		DEVICEINFO devInfo;
		if (SDF_GetDeviceInfo(hSession, &devInfo) != SDR_OK
			|| SDF_PrintDeviceInfo(&devInfo) != SDR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}

	if (key_idx >= 0) {
		if (key_idx < SDF_MIN_KEY_INDEX || key_idx > SDF_MAX_KEY_INDEX) {
			BIO_printf(bio_err, "Invalid key index\n");
			goto end;
		}
		if (!app_passwd(passarg, NULL, &pass, NULL)) {
			BIO_printf(bio_err, "Error getting password\n");
			goto end;
		}
		if (SDF_GetPrivateKeyAccessRight(hSession, (unsigned int)key_idx,
			(unsigned char *)pass, strlen(pass)) != SDR_OK) {
			OPENSSL_cleanse(pass, sizeof(pass));
			return 0;
		}
	}

	if (file_op && !label) {
		BIO_printf(bio_err, "Data object label is not assigned\n");
		goto end;
	}

	switch (file_op) {
	case FILE_OP_IMPORT:
		if (!(in = bio_open_default(infile, 'r', FORMAT_BINARY))) {
			goto opthelp;
		}
		if ((len = bio_to_mem(&buf, SDF_MAX_FILE_SIZE, in)) < 0) {
			BIO_printf(bio_err, "Error reading data object content\n");
			goto end;
		}
		if (SDF_CreateFile(hSession, (unsigned char *)label, strlen(label), len) != SDR_OK
			|| SDF_WriteFile(hSession, (unsigned char *)label, strlen(label), 0, len, buf) != SDR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}
		break;

	case FILE_OP_EXPORT:
		if (!(out = bio_open_default(outfile, 'w', FORMAT_BINARY))) {
			goto opthelp;
		}
		if (!(buf = OPENSSL_zalloc(SDF_MAX_FILE_SIZE))
			|| SDF_ReadFile(hSession, (unsigned char *)label, strlen(label), 0, &ulen, buf) != SDR_OK
			|| BIO_write(out, buf, ulen) != ulen) {
			ERR_print_errors(bio_err);
			goto end;
		}
		break;

	case FILE_OP_DELETE:
		if (SDF_DeleteFile(hSession, (unsigned char *)label, strlen(label)) != SDR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}
		break;

	case FILE_OP_NONE:
		break;
	}

	ret = 0;

end:
	BIO_free(in);
	BIO_free(out);
	OPENSSL_free(buf);
	OPENSSL_free(pass);
	if (hSession) (void)SDF_CloseSession(hSession);
	if (hDev) (void)SDF_CloseDevice(hDev);
	if (so_path) SDF_UnloadLibrary();
	return ret;
}
#endif
