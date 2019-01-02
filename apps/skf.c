/* ====================================================================
 * Copyright (c) 2014 - 2019 The GmSSL Project.  All rights reserved.
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
#ifdef OPENSSL_NO_SKF
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/pem.h>
# include <openssl/gmskf.h>
# include <openssl/gmapi.h>
# include "apps.h"

# define OP_NONE		0
# define OP_LISTDEVS		1
# define OP_DEVINFO		2
# define OP_NEWAUTHKEY		3
# define OP_LABEL		4
# define OP_LISTAPPS		5
# define OP_NEWAPP		6
# define OP_DELAPP		7
# define OP_NEWPIN		8
# define OP_UNBLOCK		10
# define OP_LISTOBJS		11
# define OP_IMPORTOBJ		12
# define OP_EXPORTOBJ		13
# define OP_DELOBJ		14
# define OP_LISTCONTAINERS	15
# define OP_NEWCONTAINER	16
# define OP_DELCONTAINER	17
# define OP_GENSM2		18
# define OP_IMPORTSM2		19
# define OP_GENRSA		20
# define OP_IMPORTRSA		21
# define OP_IMPORTCERT		22
# define OP_EXPORTCERT		23

#define SKF_DEFAULT_ADMIN_PIN_RETRY_COUNT	6
#define SKF_DEFAULT_USER_PIN_RETRY_COUNT	6


static int skf_listdevs(BIO *out);
static int skf_devinfo(const char *devname, BIO *out);
static int skf_opendev(const char *devname, const char *authkey, DEVHANDLE *hdev);
static int skf_newauthkey(DEVHANDLE hdev, const char *newauthkey);
static int skf_label(DEVHANDLE hdev, const char *label);
static int skf_listapps(DEVHANDLE hdev, BIO *out);
static int skf_newapp(DEVHANDLE hdev, const char *appname);
static int skf_delapp(DEVHANDLE hdev, const char *appname);
static int skf_openapp(DEVHANDLE hdev, const char *name, int admin, HAPPLICATION *papp);
static int skf_newpin(HAPPLICATION happ, int admin);
static int skf_unblock(HAPPLICATION happ);
static int skf_listobjs(HAPPLICATION happ, BIO *out);
static int skf_importobj(HAPPLICATION happ, const char *objname, int admin, const char *infile);
static int skf_exportobj(HAPPLICATION happ, const char *objname, BIO *out);
static int skf_delobj(HAPPLICATION happ, const char *objname);
static int skf_listcontainers(HAPPLICATION happ, BIO *out);
static int skf_newcontainer(HAPPLICATION happ, const char *containername);
static int skf_delcontainer(HAPPLICATION happ, const char *containername);
static int skf_gensm2(HCONTAINER hcontainer);
static int skf_genrsa(HCONTAINER hcontainer);
static int skf_importsm2(HCONTAINER hcontainer, const char *infile, int informat, const char *passarg);
static int skf_importrsa(HCONTAINER hcontainer, const char *infile, int informat, const char *passarg);
static int skf_importcert(HCONTAINER hcontainer, const char *infile, int informat);
static int skf_exportcert(HCONTAINER hcontainer, BIO *out, int outformat);

typedef enum OPTION_choice {
	OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
	OPT_LIB, OPT_VENDOR, OPT_LISTDEVS, OPT_DEV, OPT_DEVINFO,
	OPT_AUTHKEY, OPT_NEWAUTHKEY, OPT_LABEL,
	OPT_LISTAPPS, OPT_NEWAPP, OPT_DELAPP, OPT_APP,
	OPT_ADMIN, OPT_NEWPIN, OPT_UNBLOCK,
	OPT_LISTOBJS, OPT_OBJ, OPT_IMPORTOBJ, OPT_EXPORTOBJ, OPT_DELOBJ,
	OPT_LISTCONTAINERS, OPT_NEWCONTAINER, OPT_DELCONTAINER, OPT_CONTAINER,
	OPT_GENSM2, OPT_IMPORTSM2, OPT_GENRSA, OPT_IMPORTRSA,
	OPT_IMPORTCERT, OPT_EXPORTCERT,
	OPT_IN, OPT_OUT, OPT_INFORM, OPT_OUTFORM, OPT_PASS
} OPTION_CHOICE;

OPTIONS skf_options[] = {
	{"help", OPT_HELP, '-', "Display this summary"},
	{"lib", OPT_LIB, 's', "Load vendor's SKF dynamic library"},
	{"vendor", OPT_VENDOR, 's', "Vendor's name"},
	{"listdevs", OPT_LISTDEVS, '-', "List installed devices"},
	{"dev", OPT_DEV, 's', "Device name"},
	{"devinfo", OPT_DEVINFO, '-', "Print device information"},
	{"authkey", OPT_AUTHKEY, 's', "Device authentication key"},
	{"newauthkey", OPT_NEWAUTHKEY, 's', "New device authentication key"},
	{"label", OPT_LABEL, 's', "Set new device label"},
	{"listapps", OPT_LISTAPPS, '-', "List applications"},
	{"newapp", OPT_NEWAPP, '-', "Create new application"},
	{"delapp", OPT_DELAPP, '-', "Delete an applicaiton"},
	{"app", OPT_APP, 's', "Application's name"},
	{"admin", OPT_ADMIN, '-', "As administrator"},
	{"newpin", OPT_NEWPIN, '-', "Set a new PIN for application"},
	{"unblock", OPT_UNBLOCK, '-', "Unblock application user PIN"},
	{"listobjs", OPT_LISTOBJS, '-', "List data objects"},
	{"obj", OPT_OBJ, 's', "Data object name"},
	{"importobj", OPT_IMPORTOBJ, '-', "Import data object"},
	{"exportobj", OPT_EXPORTOBJ, '-', "Export data object"},
	{"delobj", OPT_DELOBJ, '-', "Delete data object"},
	{"listcontainers", OPT_LISTCONTAINERS, '-', "List private key containers"},
	{"newcontainer", OPT_NEWCONTAINER, '-', "Create new key container"},
	{"delcontainer", OPT_DELCONTAINER, '-', "Delete a key container"},
	{"container", OPT_CONTAINER, 's', "Key container's name"},
	{"gensm2", OPT_GENSM2, '-', "Generate SM2 signing key pair"},
	{"genrsa", OPT_GENRSA, '-', "Generate RSA key pair"},
	{"importsm2", OPT_IMPORTSM2, '-', "Import SM2 encryption key pair"},
	{"importrsa", OPT_IMPORTRSA, '-', "Import RSA encryption key pair"},
	{"importcert", OPT_IMPORTCERT, '-', "Import X.509 certificate"},
	{"exportcert", OPT_EXPORTCERT, '-', "Export X.509 certificate"},
	{"in", OPT_IN, '<', "File to be imported from"},
	{"out", OPT_OUT, '>', "File to be exported to"},
	{"inform", OPT_INFORM, 'f', "Input format - DER or PEM"},
	{"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
	{"pass", OPT_PASS, 's', "Private key password/pass-phrase source"},
	{NULL}
};

int skf_main(int argc, char **argv)
{
	int ret = 0;
	char *infile = NULL, *outfile = NULL, *prog;
	BIO *out = NULL;
	OPTION_CHOICE o;
	int informat = FORMAT_PEM, outformat = FORMAT_UNDEF;
	char *lib = NULL, *vendor = NULL, *label = NULL;
	char *authkey = NULL, *newauthkey = NULL;
	char *devname = NULL, *appname = NULL, *containername = NULL, *objname = NULL;
	char *pass = NULL, *passarg = NULL;
	int op;
	int admin = 0;

	DEVHANDLE hdev = NULL;
	HAPPLICATION happ = NULL;
	HCONTAINER hcontainer = NULL;

	prog = opt_init(argc, argv, skf_options);
	while ((o = opt_next()) != OPT_EOF) {
		switch (o) {
		case OPT_EOF:
		case OPT_ERR:
opthelp:
			BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
			goto end;
		case OPT_HELP:
			opt_help(skf_options);
			ret = 0;
			goto end;
		case OPT_LIB:
			lib = opt_arg();
			break;
		case OPT_VENDOR:
			vendor = opt_arg();
			break;
		case OPT_DEV:
			devname = opt_arg();
			break;
		case OPT_LISTDEVS:
			op = OP_LISTDEVS;
			break;
		case OPT_DEVINFO:
			op = OP_DEVINFO;
			break;
		case OPT_AUTHKEY:
			authkey = opt_arg();
			break;
		case OPT_NEWAUTHKEY:
			op = OP_NEWAUTHKEY;
			newauthkey = opt_arg();
			break;
		case OPT_LABEL:
			op = OP_LABEL;
			label = opt_arg();
			break;
		case OPT_LISTAPPS:
			op = OP_LISTAPPS;
			break;
		case OPT_NEWAPP:
			op = OP_NEWAPP;
			break;
		case OPT_DELAPP:
			op = OP_DELAPP;
			break;
		case OPT_APP:
			appname = opt_arg();
			break;
		case OPT_ADMIN:
			admin = 1;
			break;
		case OPT_NEWPIN:
			op = OP_NEWPIN;
			break;
		case OPT_UNBLOCK:
			op = OP_UNBLOCK;
			break;
		case OPT_LISTOBJS:
			op = OP_LISTOBJS;
			break;
		case OPT_OBJ:
			objname = opt_arg();
			break;
		case OPT_IMPORTOBJ:
			op = OP_IMPORTOBJ;
			break;
		case OPT_EXPORTOBJ:
			op = OP_EXPORTOBJ;
			break;
		case OPT_DELOBJ:
			op = OP_DELOBJ;
			break;
		case OPT_LISTCONTAINERS:
			op = OP_LISTCONTAINERS;
			break;
		case OPT_NEWCONTAINER:
			op = OP_NEWCONTAINER;
			break;
		case OPT_DELCONTAINER:
			op = OP_DELCONTAINER;
			break;
		case OPT_CONTAINER:
			containername = opt_arg();
			break;
		case OPT_GENSM2:
			op = OP_GENSM2;
			break;
		case OPT_IMPORTSM2:
			op = OP_IMPORTSM2;
			break;
		case OPT_GENRSA:
			op = OP_GENRSA;
			break;
		case OPT_IMPORTRSA:
			op = OP_IMPORTRSA;
			break;
		case OPT_IMPORTCERT:
			op = OP_IMPORTCERT;
			break;
		case OPT_EXPORTCERT:
			op = OP_EXPORTCERT;
			break;
		case OPT_IN:
			infile = opt_arg();
			break;
		case OPT_OUT:
			outfile = opt_arg();
			break;
		case OPT_INFORM:
			if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
				goto opthelp;
			break;
		case OPT_OUTFORM:
			if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat))
				goto opthelp;
			break;
		case OPT_PASS:
			passarg = opt_arg();
			break;
		}
	}
	argc = opt_num_rest();
	if (argc != 0)
		goto opthelp;

	if (!lib) {
		BIO_printf(bio_err, "Option `-lib' not specified\n");
		goto opthelp;
	}
	if (SKF_LoadLibrary((LPSTR)lib, (LPSTR)vendor) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	/* prepare output bio */
	switch (op) {
	case OP_LISTDEVS:
	case OP_DEVINFO:
	case OP_LISTAPPS:
	case OP_LISTOBJS:
	case OP_LISTCONTAINERS:
		if (outformat == FORMAT_UNDEF) {
			outformat = FORMAT_TEXT;
		}
		if (outformat != FORMAT_TEXT) {
			BIO_printf(bio_err, "Invalid outform option\n");
			goto opthelp;
		}
		break;
	case OP_EXPORTOBJ:
		if (outformat == FORMAT_UNDEF)
			outformat = FORMAT_BINARY;
		if (outformat != FORMAT_BINARY) {
			BIO_printf(bio_err, "Invalid outform option\n");
			goto opthelp;
		}
		break;
	case OP_EXPORTCERT:
		if (outformat == FORMAT_UNDEF) {
			outformat = FORMAT_PEM;
		}
		if (outformat != FORMAT_ASN1 && outformat != FORMAT_PEM) {
			BIO_printf(bio_err, "Invalid outform option\n");
			goto opthelp;
		}
		break;
	default:
		if (outformat != FORMAT_UNDEF) {
			BIO_printf(bio_err, "Invalid outform option\n");
			goto opthelp;
		}
	}
	if (!(out = bio_open_default(outfile, 'w', outformat))) {
		goto end;
	}

	/* without devname */
	switch (op) {
	case OP_NONE:
		ret = 1;
		goto end;
	case OP_LISTDEVS:
		ret = skf_listdevs(out);
		goto end;
	}

	/* without opendev */
	if (!devname) {
		BIO_printf(bio_err, "Error: `-dev` not specified\n");
		goto opthelp;
	}
	if (op == OP_DEVINFO) {
		ret = skf_devinfo(devname, out);
		goto end;
	}

	/* opendev */
	if (!authkey) {
		BIO_printf(bio_err, "Authentication key not specified\n");
		goto opthelp;
	}
	if (!skf_opendev(devname, authkey, &hdev)) {
		goto end;
	}

	/* without appname */
	switch (op) {
	case OP_NEWAUTHKEY:
		ret = skf_newauthkey(hdev, newauthkey);
		goto end;
	case OP_LABEL:
		ret = skf_label(hdev, label);
		goto end;
	case OP_LISTAPPS:
		ret = skf_listapps(hdev, out);
		goto end;
	}

	/* without openapp */
	if (!appname) {
		BIO_printf(bio_err, "No application name\n");
		goto opthelp;
	}
	switch (op) {
	case OP_NEWAPP:
		ret = skf_newapp(hdev, appname);
		goto end;
	case OP_DELAPP:
		ret = skf_delapp(hdev, appname);
		goto end;
	}

	/* open app */
	if (!skf_openapp(hdev, appname, admin, &happ)) {
		goto end;
	}
	switch (op) {
	case OP_NEWPIN:
		ret = skf_newpin(happ, admin);
		goto end;
	case OP_UNBLOCK:
		ret = skf_unblock(happ);
		goto end;
	case OP_LISTOBJS:
		ret = skf_listobjs(happ, out);
		goto end;
	case OP_LISTCONTAINERS:
		ret = skf_listcontainers(happ, out);
		goto end;
	}

	/* with objname */
	if ((op == OP_IMPORTOBJ || op == OP_EXPORTOBJ || op == OP_DELOBJ) && !objname) {
		BIO_printf(bio_err, "Data object name is not given\n");
		goto opthelp;
	}
	switch (op) {
	case OP_IMPORTOBJ:
		ret = skf_importobj(happ, objname, admin, infile);
		goto end;
	case OP_EXPORTOBJ:
		ret = skf_exportobj(happ, objname, out);
		goto end;
	case OP_DELOBJ:
		ret = skf_delobj(happ, objname);
		goto end;
	}

	if (!containername) {
		BIO_printf(bio_err, "No container name is given\n");
		goto opthelp;
	}
	switch (op) {
	case OP_NEWCONTAINER:
		ret = skf_newcontainer(happ, containername);
		goto end;
	case OP_DELCONTAINER:
		ret = skf_delcontainer(happ, containername);
		goto end;
	}

	if (SKF_OpenContainer(happ, (LPSTR)containername, &hcontainer) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}
	switch (op) {
	case OP_GENSM2:
		ret = skf_gensm2(hcontainer);
		break;
	case OP_GENRSA:
		ret = skf_genrsa(hcontainer);
		break;
	case OP_IMPORTSM2:
		ret = skf_importsm2(hcontainer, infile, informat, pass);
		break;
	case OP_IMPORTRSA:
		ret = skf_importrsa(hcontainer, infile, informat, pass);
		break;
	case OP_IMPORTCERT:
		ret = skf_importcert(hcontainer, infile, informat);
		break;
	case OP_EXPORTCERT:
		ret = skf_exportcert(hcontainer, out, outformat);
		break;
	}

	if (ret)
		ret = 0;
	else
		ret = 1;

end:
	if (hcontainer) SKF_CloseContainer(hcontainer);
	if (happ) SKF_CloseApplication(happ);
	if (hdev) SKF_DisConnectDev(hdev);
	return ret;
}

static int skf_listdevs(BIO *out)
{
	int ret = 0;
	BOOL bPresent = TRUE;
	char *nameList = NULL;
	ULONG nameListLen;
	const char *name;

	if (SKF_EnumDev(bPresent, NULL, &nameListLen) != SAR_OK
		|| !(nameList = OPENSSL_zalloc(nameListLen))
		|| SKF_EnumDev(bPresent, (LPSTR)nameList, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}
	for (name = nameList; *name; name += strlen(name) + 1) {
		(void)BIO_printf(out, "%s\n", name);
	}

	ret = 1;
end:
	OPENSSL_free(nameList);
	return ret;
}

static int skf_devinfo(const char *devname, BIO *out)
{
	int ret = 0;
	DEVHANDLE hdev = NULL;
	ULONG devState;
	LPSTR devStateName;
	DEVINFO devInfo = {{0,0}};

	if (SKF_GetDevState((LPSTR)devname, &devState) != SAR_OK
		|| SKF_GetDevStateName(devState, &devStateName) != SAR_OK
		|| SKF_ConnectDev((LPSTR)devname, &hdev) != SAR_OK
		|| SKF_GetDevInfo(hdev, &devInfo) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	(void)BIO_printf(out, "  %-16s : %s\n", "Device Name", devname);
	(void)BIO_printf(out, "  %-16s : %s\n", "Device State", (char *)devStateName);
	(void)SKF_PrintDevInfo(&devInfo);
	(void)BIO_printf(out, "\n");
	ret = 1;

end:
	if (hdev && SKF_DisConnectDev(hdev) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_opendev(const char *devName, const char *authkeyhex, DEVHANDLE *pdev)
{
	int ret = 0;
	DEVHANDLE hDev = NULL;
	HANDLE hKey = NULL;
	ULONG ulTimeOut = 0xffffffff;
	unsigned char *authkey = NULL;
	DEVINFO devInfo = {{0,0}};
	BYTE authRand[16] = {0};
	BYTE authData[16] = {0};
	ULONG authRandLen = SKF_AUTHRAND_LENGTH;
	ULONG authDataLen = sizeof(authData);
	BLOCKCIPHERPARAM encParam = {{0}, 0, 0, 0};
	long len;

	if (!(authkey = OPENSSL_hexstr2buf(authkeyhex, &len))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (len != 16) {
		BIO_printf(bio_err, "Invlaid authentication key length\n");
		goto end;
	}

	if (SKF_ConnectDev((LPSTR)devName, &hDev) != SAR_OK
		|| SKF_GetDevInfo(hDev, &devInfo) != SAR_OK
		|| SKF_LockDev(hDev, ulTimeOut) != SAR_OK
		|| SKF_GenRandom(hDev, authRand, authRandLen) != SAR_OK
		|| SKF_SetSymmKey(hDev, authkey, devInfo.DevAuthAlgId, &hKey) != SAR_OK
		|| SKF_EncryptInit(hKey, encParam) != SAR_OK
		|| SKF_Encrypt(hKey, authRand, sizeof(authRand), authData, &authDataLen) != SAR_OK
		|| SKF_DevAuth(hDev, authData, authDataLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}
	*pdev = hDev;
	hDev = NULL;
	ret = 1;

end:
	OPENSSL_cleanse(authkey, len);
	OPENSSL_cleanse(authRand, sizeof(authRand));
	OPENSSL_cleanse(authData, sizeof(authData));
	if (hDev  && ( SKF_UnlockDev(hDev) != SAR_OK
		|| SKF_DisConnectDev(hDev) != SAR_OK)) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_openapp(DEVHANDLE hdev, const char *name, int admin, HAPPLICATION *papp)
{
	int ret = 0;
	HAPPLICATION hApp = NULL;
	CHAR szPin[64] = {0};
	ULONG numRetry;
	ULONG user_type = admin ? ADMIN_TYPE : USER_TYPE;

	if (SKF_OpenApplication(hdev, (LPSTR)name, &hApp) != SAR_OK
		|| EVP_read_pw_string((char *)szPin, sizeof(szPin), "PIN > ", 0) < 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (SKF_VerifyPIN(hApp, user_type, szPin, &numRetry) != SAR_OK) {
		BIO_printf(bio_err, "Invalid %s PIN, retry count = %u\n",
			admin ? "admin" :  "user", numRetry);
		ERR_print_errors(bio_err);
		goto end;
	}
	*papp = hApp;
	hApp = NULL;
	ret = 1;

end:
	if (hApp && SKF_CloseApplication(hApp) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_newauthkey(DEVHANDLE hdev, const char *newauthkey)
{
	int ret = 0;
	unsigned char *authkey = NULL;
	long len;

	if (!(authkey = OPENSSL_hexstr2buf(newauthkey, &len))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (len != 16) {
		BIO_printf(bio_err, "Invalid authentication key legnth\n");
		goto end;
	}
	if (SKF_ChangeDevAuthKey(hdev, authkey, len) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 1;

end:
	OPENSSL_clear_free(authkey, len);
	return ret;
}

static int skf_label(DEVHANDLE hdev, const char *label)
{
	if (SKF_SetLabel(hdev, (LPSTR)label) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	return 1;
}

static int skf_listapps(DEVHANDLE hdev, BIO *out)
{
	int ret = 0;
	HAPPLICATION hApp = NULL;
	char *nameList = NULL;
	ULONG nameListLen;
	const char *name;

	if (SKF_EnumApplication(hdev, NULL, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	if (!nameListLen) {
		BIO_printf(out, "no application\n");
		return 1;
	}

	if (!(nameList = OPENSSL_malloc(nameListLen))) {
		ERR_print_errors(bio_err);
		return 0;
	}
	if (SKF_EnumApplication(hdev, (LPSTR)nameList, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	for (name = nameList; *name; name += strlen(name) + 1) {
		ULONG adminMaxRetry;
		ULONG adminMinRetry;
		ULONG userMaxRetry;
		ULONG userMinRetry;
		BOOL adminDefaultPin, userDefaultPin;

		if (SKF_OpenApplication(hdev, (LPSTR)name, &hApp) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}

		if (SKF_GetPINInfo(hApp, ADMIN_TYPE, &adminMaxRetry,
			&adminMinRetry, &adminDefaultPin) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (SKF_GetPINInfo(hApp, USER_TYPE, &userMaxRetry,
			&userMinRetry, &userDefaultPin) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (SKF_CloseApplication(hApp) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}
		hApp = NULL;

		(void)BIO_printf(out, "%-16s : %s\n", "Application", name);
		(void)BIO_printf(out, "%-16s : %u\n", "AdminPinMaxRetry", adminMaxRetry);
		(void)BIO_printf(out, "%-16s : %u\n", "AdminPinMinRetry", adminMinRetry);
		(void)BIO_printf(out, "%-16s : %s\n", "AdminDefaultPin", adminDefaultPin ? "True" : "False");
		(void)BIO_printf(out, "%-16s : %u\n", "UserPinMaxRetry", userMaxRetry);
		(void)BIO_printf(out, "%-16s : %u\n", "UserPinMinRetry", userMinRetry);
		(void)BIO_printf(out, "%-16s : %s\n", "UserDefaultPin", userDefaultPin ? "True" : "False");
		(void)BIO_puts(out, "\n");
	}

	ret = 1;

end:
	if (hApp && SKF_CloseApplication(hApp) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_newapp(DEVHANDLE hdev, const char *appname)
{
	int ret = 0;
	CHAR szAdminPin[64] = {0};
	CHAR szUserPin[64] = {0};
	HAPPLICATION hApp = NULL;
	ULONG skf_app_rights = SECURE_ANYONE_ACCOUNT;

	if (EVP_read_pw_string((char *)szAdminPin, sizeof(szAdminPin),
		"Admin PIN > ", 1) < 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (EVP_read_pw_string((char *)szUserPin, sizeof(szUserPin),
		"User PIN > ", 1) < 0) {
		ERR_print_errors(bio_err);
		goto end;
	}

	if (SKF_CreateApplication(hdev, (LPSTR)appname,
		szAdminPin, SKF_DEFAULT_ADMIN_PIN_RETRY_COUNT,
		szUserPin, SKF_DEFAULT_USER_PIN_RETRY_COUNT,
		skf_app_rights, &hApp) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 1;

end:
	OPENSSL_cleanse(szAdminPin, sizeof(szAdminPin));
	OPENSSL_cleanse(szUserPin, sizeof(szUserPin));
	if (hApp && SKF_CloseApplication(hApp) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_delapp(DEVHANDLE hdev, const char *appname)
{
	if (SKF_DeleteApplication(hdev, (LPSTR)appname) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	return 1;
}

static int skf_newpin(HAPPLICATION happ, int admin)
{
	int ret = 0;
	ULONG rv;
	CHAR szOldPin[64] = {0};
	CHAR szNewPin[64] = {0};
	ULONG ulPINType = admin ? ADMIN_TYPE : USER_TYPE;
	ULONG ulRetryCount = 0;

	if (EVP_read_pw_string((char *)szOldPin, sizeof(szOldPin),
		"Old PIN > ", 0) <  0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (EVP_read_pw_string((char *)szNewPin, sizeof(szNewPin),
		"New PIN > ", 1) < 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if ((rv = SKF_ChangePIN(happ, ulPINType, szOldPin, szNewPin,
		&ulRetryCount)) != SAR_OK) {
		BIO_printf(bio_err, "Retry Count = %u\n", ulRetryCount);
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 1;
end:
	OPENSSL_cleanse(szOldPin, sizeof(szOldPin));
	OPENSSL_cleanse(szNewPin, sizeof(szNewPin));
	return ret;
}

static int skf_unblock(HAPPLICATION happ)
{
	int ret = 0;
	CHAR szAdminPIN[64];
	CHAR szNewUserPIN[64];
	ULONG ulRetryCount = 0;

	if (EVP_read_pw_string((char *)szAdminPIN, sizeof(szAdminPIN), "Admin PIN > ", 0) < 0
		|| EVP_read_pw_string((char *)szNewUserPIN, sizeof(szNewUserPIN), "New User PIN > ", 1) < 0
		|| SKF_UnblockPIN(happ, szAdminPIN, szNewUserPIN, &ulRetryCount) != SAR_OK) {
		BIO_printf(bio_err, "Invalid admin PIN, retry count = %u\n", ulRetryCount);
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 1;
end:
	OPENSSL_cleanse(szAdminPIN, sizeof(szAdminPIN));
	OPENSSL_cleanse(szNewUserPIN, sizeof(szNewUserPIN));
	return ret;
}

static int skf_listobjs(HAPPLICATION happ, BIO *out)
{
	int ret = 0;
	char *nameList = NULL;
	ULONG nameListLen;
	const char *name;

	if (SKF_EnumFiles(happ, NULL, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}

	if (!(nameList = OPENSSL_malloc(nameListLen))) {
		ERR_print_errors(bio_err);
		return 0;
	}

	if (SKF_EnumFiles(happ, (LPSTR)nameList, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	BIO_printf(out, "nameList : %s\n", nameList);

	for (name = nameList; *name; name += strlen(name) + 1) {
		FILEATTRIBUTE fileInfo;

		if (SKF_GetFileInfo(happ, (LPSTR)name, &fileInfo) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}

		BIO_printf(out, "  %-16s : %s\n", "File Name", (char *)&(fileInfo.FileName));
		BIO_printf(out, "  %-16s : %u\n", "File Size", fileInfo.FileSize);
		BIO_printf(out, "  %-16s : %8X\n", "Read Rights", fileInfo.ReadRights);
		BIO_printf(out, "  %-16s : %8X\n", "Write Rights", fileInfo.WriteRights);
		BIO_printf(out, "\n");
	}

	ret = 1;

end:
	OPENSSL_free(nameList);
	return ret;
}

static int skf_importobj(HAPPLICATION happ, const char *objname, int admin, const char *infile)
{
	int ret = 0;
	BIO *in = NULL;
	ULONG ulReadRights = SECURE_ANYONE_ACCOUNT;
	ULONG ulWriteRights = SECURE_USER_ACCOUNT;
	unsigned char *buf = NULL;
	int len = SKF_MAX_FILE_SIZE;

	if (admin) {
		ulWriteRights = SECURE_ADM_ACCOUNT;
	}

	if (!(in = bio_open_default(infile, 'r', FORMAT_BINARY))) {
		goto end;
	}
	if ((len = bio_to_mem(&buf, SKF_MAX_FILE_SIZE, in)) <= 0) {
		goto end;
	}

	(void)BIO_printf(bio_err, "file name = %s\n", objname);
	(void)BIO_printf(bio_err, "file size = %d\n", len);

	if (SKF_CreateFile(happ, (LPSTR)objname, len,
		ulReadRights, ulWriteRights) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	if (SKF_WriteFile(happ, (LPSTR)objname, 0, buf, len) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	(void)BIO_printf(bio_err, "import object success\n");
	ret = 1;
end:
	OPENSSL_free(buf);
	return ret;
}

static int skf_exportobj(HAPPLICATION happ, const char *objname, BIO *out)
{
	int ret = 0;
	FILEATTRIBUTE fileInfo;
	unsigned char *buf = NULL;
	ULONG len = SKF_MAX_FILE_SIZE;

	if (SKF_GetFileInfo(happ, (LPSTR)objname, &fileInfo) != SAR_OK
		|| !(buf = OPENSSL_malloc(fileInfo.FileSize))
		|| SKF_ReadFile(happ, (LPSTR)objname, 0, fileInfo.FileSize, buf, &len) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	if (len != fileInfo.FileSize) {
		BIO_printf(bio_err, "Error on reading object\n");
		goto end;
	}

	if (BIO_write(out, buf, (int)len) != (int)len) {
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 1;

end:
	OPENSSL_free(buf);
	return ret;
}

static int skf_delobj(HAPPLICATION happ, const char *objname)
{
	if (SKF_DeleteFile(happ, (LPSTR)objname) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	(void)BIO_printf(bio_err, "Object `%s' deleted\n", objname);
	return 1;
}

static int skf_listcontainers(HAPPLICATION happ, BIO *out)
{
	int ret = 0;
	HCONTAINER hContainer = NULL;
	char *nameList = NULL;
	ULONG nameListLen;
	const char *name;

	if (SKF_EnumContainer(happ, NULL, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	if (!nameListLen) {
		BIO_printf(out, "no container\n");
		return 1;
	}
	if (!(nameList = OPENSSL_malloc(nameListLen))) {
		ERR_print_errors(bio_err);
		return 0;
	}
	if (SKF_EnumContainer(happ, (LPSTR)nameList, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	for (name = nameList; *name; name += strlen(name) + 1) {
		ULONG containerType;
		LPSTR containerTypeName;

		if (SKF_OpenContainer(happ, (LPSTR)name, &hContainer) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (SKF_GetContainerType(hContainer, &containerType) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (SKF_GetContainerTypeName(containerType, &containerTypeName) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (SKF_CloseContainer(hContainer) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}
		hContainer = NULL;

		(void)BIO_printf(out, "    Container Name : %s\n", name);
		(void)BIO_printf(out, "    Container Type : %s\n", (char *)containerTypeName);
		(void)BIO_printf(out, "\n");
	}

	ret = 1;

end:
	if (hContainer && SKF_CloseContainer(hContainer) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_newcontainer(HAPPLICATION happ, const char *containername)
{
	HCONTAINER hContainer = NULL;
	if (SKF_CreateContainer(happ, (LPSTR)containername, &hContainer) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	(void)BIO_printf(bio_err, "container `%s' created\n", containername);

	if (SKF_CloseContainer(hContainer) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	return 1;
}

static int skf_delcontainer(HAPPLICATION happ, const char *containername)
{
	if (SKF_DeleteContainer(happ, (LPSTR)containername) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	return 1;
}

static int skf_gensm2(HCONTAINER hContainer)
{
	int ret = 0;
	ULONG containerType;
	ECCPUBLICKEYBLOB eccPublicKeyBlob;

	if (SKF_GetContainerType(hContainer, &containerType) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (containerType != SKF_CONTAINER_TYPE_UNDEF) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (SKF_GenECCKeyPair(hContainer, SGD_SM2_1, &eccPublicKeyBlob) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	SKF_PrintECCPublicKey(&eccPublicKeyBlob);
	ret = 1;

end:
	return ret;
}

static int skf_genrsa(HCONTAINER hcontainer)
{
	fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
	return 0;
}

static int skf_importsm2(HCONTAINER hcontainer, const char *infile,
	int informat, const char *passarg)
{
	fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
	return 0;
}

static int skf_importrsa(HCONTAINER hcontainer, const char *infile, int informat, const char *passarg)
{
	fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
	return 0;
}

static int skf_importcert(HCONTAINER hcontainer, const char *infile, int informat)
{
	fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
	return 0;
}

static int skf_exportcert(HCONTAINER hcontainer, BIO *out, int outformat)
{
	fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
	return 0;
}
#endif
