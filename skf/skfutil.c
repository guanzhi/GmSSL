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
# include <openssl/sms4.h>
# include <openssl/gmskf.h>
# include <openssl/gmapi.h>
# include "apps.h"


# define OP_NONE		0
# define OP_LISTDEVS		1
# define OP_DEVINFO		2
# define OP_NEWAUTHKEY		3
# define OP_LABEL		4
# define OP_TRANSMIT		5
# define OP_LISTAPPS		6
# define OP_NEWAPP		7
# define OP_DELAPP		8
# define OP_CHANGEPASS		9
# define OP_UNBLOCK		10
# define OP_LISTOBJS		11
# define OP_IMPORTOBJ		12
# define OP_EXPORTOBJ		13
# define OP_DELOBJ		14
# define OP_LISTCONTAINERS	15
# define OP_NEWCONTAINER	16
# define OP_DELCONTAINER	17
# define OP_IMPORTENCKEY	18
# define OP_EXPORTSIGNKEY	19
# define OP_EXPORTENCKEY	20
# define OP_PRINTKEYS		21
# define OP_IMPORTCERT		22
# define OP_EXPORTSIGNCERT	23
# define OP_EXPORTENCCERT	24

typedef enum OPTION_choice {
	OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
	OPT_LIB, OPT_VENDOR, OPT_LISTDEVS, OPT_DEV, OPT_DEVINFO, OPT_LABEL,
	OPT_TRANSMIT, OPT_AUTHKEY, OPT_NEWAUTHKEY, OPT_LISTAPPS, OPT_NEWAPP,
	OPT_DELAPP, OPT_APP, OPT_CHANGEPASS, OPT_PASS, OPT_ADMIN, OPT_ADMINPASS,
	OPT_NEWPASS, OPT_UNBLOCK, OPT_LISTOBJS, OPT_IMPORTOBJ, OPT_EXPORTOBJ,
	OPT_DELOBJ, OPT_OBJ, OPT_LISTCONTAINERS, OPT_NEWCONTAINER, OPT_ALGORITHM,
	OPT_DELCONTAINER, OPT_CONTAINER, OPT_IMPORTENCKEY, OPT_KEYPASS,
	OPT_EXPORTSIGNKEY, OPT_EXPORTENCKEY, OPT_PRINTKEYS,
	OPT_IMPORTCERT, OPT_EXPORTSIGNCERT, OPT_EXPORTENCCERT,
	OPT_IN, OPT_OUT, OPT_INFORM, OPT_OUTFORM,
} OPTION_CHOICE;

OPTIONS skf_options[] = {
	{"help", OPT_HELP, '-', "Display this summary"},
	{"lib", OPT_LIB, 's', "Vendor's SKF dynamic library"},
	{"vendor", OPT_VENDOR, 's', "Vendor name"},
	{"listdevs", OPT_LISTDEVS, '-', "List installed devices"},
	{"dev", OPT_DEV, 's', "Device name"},
	{"devinfo", OPT_DEVINFO, '-', "Print device information"},
	{"label", OPT_LABEL, 's', "Set new device label"},
	{"transmit", OPT_TRANSMIT, 's', "Transmit raw data packet"},
	{"authkey", OPT_AUTHKEY, 's', "Device authentication key in Hex"},
	{"newauthkey", OPT_NEWAUTHKEY, 's', "Set new device authentication key in Hex"},
	{"listapps", OPT_LISTAPPS, '-', "List applications"},
	{"newapp", OPT_NEWAPP, 's', "Create a new application with name"},
	{"delapp", OPT_DELAPP, 's', "Delete an applicaiton by name"},
	{"app", OPT_APP, 's', "Application name"},
	{"changepass", OPT_CHANGEPASS, '-', "Change application user or admin passw-phrase"},
	{"admin", OPT_ADMIN, '-', "Open application as administrator"},
	{"pass", OPT_PASS, 's', "Application user or admin pass-phrase source"},
	{"newpass", OPT_NEWPASS, 's', "Application user or admin new ass-phrase source"},
	{"adminpass", OPT_ADMINPASS, 's', "Application admin pass-phrase source"},
	{"unblock", OPT_UNBLOCK, '-', "Unblock application user pass-phrase"},
	{"listobjs", OPT_LISTOBJS, '-', "List data objects"},
	{"importobj", OPT_IMPORTOBJ, 's', "Import data object with name"},
	{"exportobj", OPT_EXPORTOBJ, 's', "Export data object by name"},
	{"delobj", OPT_DELOBJ, 's', "Delete data object by name"},
	{"obj", OPT_OBJ, 's', "Data object name"},
	{"listcontainers", OPT_LISTCONTAINERS, '-', "List containers"},
	{"newcontainer", OPT_NEWCONTAINER, 's', "Create container with name"},
	{"algorithm", OPT_ALGORITHM, 's', "Container public key algorithm - SM2 or RSA"},
	{"delcontainer", OPT_DELCONTAINER, 's', "Delete container by name"},
	{"container", OPT_CONTAINER, 's', "Container name"},
	{"importenckey", OPT_IMPORTENCKEY, '-', "Import encryption private key into container"},
	{"keypass", OPT_KEYPASS, 's', "Private key encryption pass-phrase"},
	{"exportsignkey", OPT_EXPORTSIGNKEY, '-', "Export signing public key from container"},
	{"exportenckey", OPT_EXPORTENCKEY, '-', "Export encryption public key from container"},
	{"printkeys", OPT_PRINTKEYS, '-', "Print public keys in container"},
	{"importcert", OPT_IMPORTCERT, '-', "Import certificate into container"},
	{"exportsigncert", OPT_EXPORTSIGNCERT, '-', "Export signing certificate from container"},
	{"exportenccert", OPT_EXPORTENCCERT, '-', "Export encryption certificate from container"},
	{"in", OPT_IN, '<', "File to be imported from"},
	{"out", OPT_OUT, '>', "File to be exported to"},
	{"inform", OPT_INFORM, 'f', "Input format - DER or PEM"},
	{"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
	{NULL}
};

static int skf_listdevs(BIO *out)
{
	int ret = 0;
	BOOL bPresent = TRUE;
	char *nameList = NULL;
	ULONG nameListLen;
	const char *name;
	int i;

	if (SKF_EnumDev(bPresent, NULL, &nameListLen) != SAR_OK
		|| !(nameList = OPENSSL_zalloc(nameListLen))
		|| SKF_EnumDev(bPresent, (LPSTR)nameList, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}
	for (name = nameList, i = 0; *name; name += strlen(name) + 1, i++) {
		(void)BIO_printf(out, "  Device %d : %s\n", i, name);
	}

	ret = 1;
end:
	OPENSSL_free(nameList);
	return ret;
}

static int skf_devinfo(const char *devname, BIO *out)
{
	int ret = 0;
	DEVHANDLE hDev = NULL;
	ULONG devState;
	LPSTR devStateName;
	DEVINFO devInfo = {{0,0}};

	if (SKF_GetDevState((LPSTR)devname, &devState) != SAR_OK
		|| SKF_GetDevStateName(devState, &devStateName) != SAR_OK
		|| SKF_ConnectDev((LPSTR)devname, &hDev) != SAR_OK
		|| SKF_GetDevInfo(hDev, &devInfo) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	(void)BIO_printf(out, "Device %s :\n", devname);
	(void)BIO_printf(out, "  %-16s : %s\n", "Device State", (char *)devStateName);
	(void)SKF_PrintDevInfo(out, &devInfo);
	(void)BIO_puts(out, "\n");
	ret = 1;

end:
	if (hDev && SKF_DisConnectDev(hDev) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_label(const char *devname, const char *label)
{
	int ret = 0;
	DEVHANDLE hDev = NULL;
	ULONG ulTimeOut = 0xffffffff;

	if (SKF_ConnectDev((LPSTR)devname, &hDev) != SAR_OK
		|| SKF_LockDev(hDev, ulTimeOut) != SAR_OK
		|| SKF_SetLabel(hDev, (LPSTR)label) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 1;
end:
	if (hDev && SKF_DisConnectDev(hDev) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_transmit(const char *devName, const char *cmd, BIO *out)
{
	int ret = 0;
	BYTE *inbuf = NULL;
	long inlen;
	DEVHANDLE hDev = NULL;
	BYTE outbuf[256];
	ULONG outlen = sizeof(outbuf);

	if (!(inbuf = OPENSSL_hexstr2buf(cmd, &inlen))
		|| SKF_ConnectDev((LPSTR)devName, &hDev) != SAR_OK
		|| SKF_Transmit(hDev, inbuf, (ULONG)inlen, outbuf, &outlen) != SAR_OK
		|| BIO_write(out, outbuf, (int)outlen) != outlen) {
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 1;
end:
	OPENSSL_free(inbuf);
	if (hDev && SKF_DisConnectDev(hDev) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_opendev(const char *devname, const char *authkeyhex,
	DEVINFO *devInfo, DEVHANDLE *phDev)
{
	int ret = 0;
	unsigned char *authKey = NULL;
	long len;

	if (!(authKey = OPENSSL_hexstr2buf(authkeyhex, &len))) {
		BIO_printf(bio_err, "Error on parsing authentication key\n");
		ERR_print_errors(bio_err);
		return 0;
	}
	if (len != 16) {
		BIO_printf(bio_err, "Invlaid authentication key length\n");
		goto end;
	}
	if (SKF_OpenDevice((LPSTR)devname, authKey, devInfo, phDev) != SAR_OK) {
		BIO_printf(bio_err, "Error on opening device\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 1;

end:
	OPENSSL_clear_free(authKey, len);
	return ret;
}

static int skf_newauthkey(DEVHANDLE hDev, const char *authkeyhex)
{
	int ret = 0;
	unsigned char *authKey = NULL;
	long len;

	if (!(authKey = OPENSSL_hexstr2buf(authkeyhex, &len))) {
		BIO_printf(bio_err, "Error on parsing new authentication key\n");
		ERR_print_errors(bio_err);
		return 0;
	}
	if (len != 16) {
		BIO_printf(bio_err, "Invalid new authentication key legnth\n");
		goto end;
	}
	if (SKF_ChangeDevAuthKey(hDev, authKey, len) != SAR_OK) {
		BIO_printf(bio_err, "Error on changing authentication key\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 1;

end:
	OPENSSL_clear_free(authKey, len);
	return ret;
}

static int skf_listapps(DEVHANDLE hDev, BIO *out)
{
	int ret = 0;
	HAPPLICATION hApp = NULL;
	char *nameList = NULL;
	ULONG nameListLen;
	const char *name;
	int i;

	if (SKF_EnumApplication(hDev, NULL, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	if (nameListLen <= 1) {
		BIO_printf(out, "No application found\n");
		return 1;
	}
	if (!(nameList = OPENSSL_zalloc(nameListLen))) {
		ERR_print_errors(bio_err);
		return 0;
	}
	if (SKF_EnumApplication(hDev, (LPSTR)nameList, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	for (name = nameList, i = 0; *name; name += strlen(name) + 1, i++) {
		ULONG adminMaxRetry;
		ULONG adminMinRetry;
		ULONG userMaxRetry;
		ULONG userMinRetry;
		BOOL adminDefaultPin, userDefaultPin;

		if (SKF_OpenApplication(hDev, (LPSTR)name, &hApp) != SAR_OK) {
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

		(void)BIO_printf(out, "Application %d:\n", i);
		(void)BIO_printf(out, "  %-16s : %s\n", "ApplicationName", name);
		(void)BIO_printf(out, "  %-16s : %u\n", "AdminPinMaxRetry", adminMaxRetry);
		(void)BIO_printf(out, "  %-16s : %u\n", "AdminPinMinRetry", adminMinRetry);
		(void)BIO_printf(out, "  %-16s : %s\n", "AdminDefaultPin", adminDefaultPin ? "True" : "False");
		(void)BIO_printf(out, "  %-16s : %u\n", "UserPinMaxRetry", userMaxRetry);
		(void)BIO_printf(out, "  %-16s : %u\n", "UserPinMinRetry", userMinRetry);
		(void)BIO_printf(out, "  %-16s : %s\n", "UserDefaultPin", userDefaultPin ? "True" : "False");
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

static int skf_newapp(DEVHANDLE hDev, const char *appname, const char *pass, const char *adminpass)
{
	int ret = 0;
	CHAR *szAdminPin = NULL;
	CHAR *szUserPin = NULL;
	HAPPLICATION hApp = NULL;
	ULONG skf_app_rights = SECURE_ANYONE_ACCOUNT;

	if (!app_passwd(pass, adminpass, (char **)&szUserPin, (char **)&szAdminPin)) {
		BIO_printf(bio_err, "No application found\n");
		goto end;
	}

	if (!pass) {
		int len = 64;
		if (!(szUserPin = OPENSSL_zalloc(len))
			|| EVP_read_pw_string((char *)szUserPin, len, "User PIN > ", 1) < 0) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}

	if (!adminpass) {
		int len = 64;
		if (!(szAdminPin = OPENSSL_zalloc(len))
			|| EVP_read_pw_string((char *)szAdminPin, len, "Admin PIN > ", 1) < 0) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}

	if (SKF_CreateApplication(hDev, (LPSTR)appname,
		szAdminPin, SKF_DEFAULT_ADMIN_PIN_RETRY_COUNT,
		szUserPin, SKF_DEFAULT_USER_PIN_RETRY_COUNT,
		skf_app_rights, &hApp) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	BIO_printf(bio_err, "Application '%s' created\n", appname);
	ret = 1;

end:
	OPENSSL_clear_free(szUserPin, strlen((char *)szUserPin));
	OPENSSL_clear_free(szAdminPin, strlen((char *)szAdminPin));
	if (hApp && SKF_CloseApplication(hApp) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_delapp(DEVHANDLE hDev, const char *appname)
{
	if (SKF_DeleteApplication(hDev, (LPSTR)appname) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	return 1;
}

static int skf_changepass(DEVHANDLE hDev, const char *appname,
	int admin, const char *pass, const char *newpass)
{
	int ret = 0;
	HAPPLICATION hApp = NULL;
	ULONG ulPINType = admin ? ADMIN_TYPE : USER_TYPE;
	CHAR *szOldPin = NULL;
	CHAR *szNewPin = NULL;
	ULONG ulRetryCount = 0;

	if (SKF_OpenApplication(hDev, (LPSTR)appname, &hApp) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	if (!pass || !newpass) {
		int len = 64;
		if (!(szOldPin = OPENSSL_zalloc(len))
			|| !(szNewPin = OPENSSL_zalloc(len))
			|| EVP_read_pw_string((char *)szOldPin, len, "Old PIN > ", 0) < 0
			|| EVP_read_pw_string((char *)szNewPin, len, "New PIN > ", 0) < 0) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}

	if (!app_passwd(pass, newpass, (char **)&szOldPin, (char **)&szNewPin)) {
		BIO_puts(bio_err, "Error getting password\n");
		return 0;
	}

	if (SKF_ChangePIN(hApp, ulPINType, szOldPin, szNewPin,
		&ulRetryCount) != SAR_OK) {
		BIO_printf(bio_err, "Retry Count = %u\n", ulRetryCount);
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 1;
end:
	OPENSSL_clear_free(szOldPin, sizeof(szOldPin));
	OPENSSL_clear_free(szNewPin, sizeof(szNewPin));
	if (hApp && SKF_CloseApplication(hApp) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_unblock(DEVHANDLE hDev, const char *appname,
	const char *adminpassarg, const char *userpassarg)
{
	int ret = 0;
	HAPPLICATION hApp = NULL;
	CHAR *szAdminPin = NULL;
	CHAR *szNewUserPin = NULL;
	ULONG ulRetryCount = 0;

	if (SKF_OpenApplication(hDev, (LPSTR)appname, &hApp) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	if (!adminpassarg) {
		int len = 64;
		if (!(szAdminPin = OPENSSL_zalloc(len))
			|| EVP_read_pw_string((char *)szAdminPin, len, "Admin PIN > ", 0) < 0) {
			ERR_print_errors(bio_err);
			goto end;
		}
	} else {
		if (!app_passwd(adminpassarg, NULL, (char **)&szAdminPin, NULL)) {
			BIO_puts(bio_err, "Error getting password\n");
			goto end;
		}
	}

	if (!userpassarg) {
		int len = 64;
		if (!(szNewUserPin = OPENSSL_zalloc(len))
			|| EVP_read_pw_string((char *)szNewUserPin, len, "New User PIN > ", 0) < 0) {
			ERR_print_errors(bio_err);
			goto end;
		}
	} else {
		if (!app_passwd(userpassarg, NULL, (char **)&szNewUserPin, NULL)) {
			BIO_puts(bio_err, "Error getting password\n");
			goto end;
		}
	}

	if (SKF_UnblockPIN(hApp, szAdminPin, szNewUserPin, &ulRetryCount) != SAR_OK) {
		BIO_printf(bio_err, "Invalid admin PIN, retry count = %u\n", ulRetryCount);
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 1;
end:
	OPENSSL_clear_free(szAdminPin, strlen((char *)szAdminPin));
	OPENSSL_clear_free(szNewUserPin, strlen((char *)szNewUserPin));
	if (hApp && SKF_CloseApplication(hApp) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_openapp(DEVHANDLE hDev, const char *name, int admin,
	const char *passarg, HAPPLICATION *phApp)
{
	int ret = 0;
	HAPPLICATION hApp = NULL;
	CHAR *szPin = NULL;
	ULONG numRetry;
	ULONG user_type = admin ? ADMIN_TYPE : USER_TYPE;

	if (SKF_OpenApplication(hDev, (LPSTR)name, &hApp) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}

	if (passarg) {
		if (!app_passwd(passarg, NULL, (char **)&szPin, NULL)) {
			BIO_printf(bio_err, "Error on reading password\n");
			goto end;
		}
	} else {
		int len = 64;
		if (!(szPin = OPENSSL_zalloc(len))
			|| EVP_read_pw_string((char *)szPin, len, "PIN >", 0) < 0) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}

	if (SKF_VerifyPIN(hApp, user_type, szPin, &numRetry) != SAR_OK) {
		BIO_printf(bio_err, "Invalid %s PIN, retry count = %u\n",
			admin ? "admin" :  "user", numRetry);
		ERR_print_errors(bio_err);
		goto end;
	}
	*phApp = hApp;
	hApp = NULL;
	ret = 1;

end:

	OPENSSL_clear_free(szPin, strlen((char *)szPin));
	if (hApp && SKF_CloseApplication(hApp) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_listobjs(HAPPLICATION hApp, BIO *out)
{
	int ret = 0;
	char *nameList = NULL;
	ULONG nameListLen;
	const char *name;
	int i;

	if (SKF_EnumFiles(hApp, NULL, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}

	if (!(nameList = OPENSSL_malloc(nameListLen))) {
		ERR_print_errors(bio_err);
		return 0;
	}

	if (SKF_EnumFiles(hApp, (LPSTR)nameList, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	for (name = nameList, i = 0; *name; name += strlen(name) + 1, i++) {
		FILEATTRIBUTE fileInfo;

		if (SKF_GetFileInfo(hApp, (LPSTR)name, &fileInfo) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}

		BIO_printf(out, "Object %d:\n", i);
		BIO_printf(out, "  %-16s : %s\n", "Object Name", (char *)&(fileInfo.FileName));
		BIO_printf(out, "  %-16s : %u\n", "Object Size", fileInfo.FileSize);
		BIO_printf(out, "  %-16s : %08X\n", "Read Rights", fileInfo.ReadRights);
		BIO_printf(out, "  %-16s : %08X\n", "Write Rights", fileInfo.WriteRights);
		BIO_puts(out, "\n");
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

	if (SKF_CreateFile(happ, (LPSTR)objname, len,
		ulReadRights, ulWriteRights) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	if (SKF_WriteFile(happ, (LPSTR)objname, 0, buf, len) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	BIO_printf(bio_err, "Object '%s' (%u bytes) created\n", objname, len);
	ret = 1;

end:
	OPENSSL_free(buf);
	return ret;
}

static int skf_exportobj(HAPPLICATION hApp, const char *objname, BIO *out)
{
	int ret = 0;
	FILEATTRIBUTE fileInfo;
	unsigned char *buf = NULL;
	ULONG ulen = SKF_MAX_FILE_SIZE;
	int len;

	if (SKF_GetFileInfo(hApp, (LPSTR)objname, &fileInfo) != SAR_OK
		|| !(buf = OPENSSL_malloc(fileInfo.FileSize))
		|| SKF_ReadFile(hApp, (LPSTR)objname, 0, fileInfo.FileSize, buf, &ulen) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	if (ulen != fileInfo.FileSize) {
		BIO_printf(bio_err, "Error on reading object\n");
		goto end;
	}

	if ((len = BIO_write(out, buf, (int)ulen)) != (int)ulen) {
		ERR_print_errors(bio_err);
		goto end;
	}
	(void)BIO_printf(bio_err, "%d bytes exportd\n", len);

	ret = 1;

end:
	OPENSSL_free(buf);
	return ret;
}

static int skf_delobj(HAPPLICATION hApp, const char *objname)
{
	if (SKF_DeleteFile(hApp, (LPSTR)objname) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	return 1;
}

static int skf_listcontainers(HAPPLICATION hApp, BIO *out)
{
	int ret = 0;
	HCONTAINER hContainer = NULL;
	char *nameList = NULL;
	ULONG nameListLen;
	const char *name;
	int i;

	if (SKF_EnumContainer(hApp, NULL, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	if (!nameListLen) {
		(void)BIO_puts(bio_err, "No container found\n");
		return 1;
	}
	if (!(nameList = OPENSSL_malloc(nameListLen))) {
		ERR_print_errors(bio_err);
		return 0;
	}
	if (SKF_EnumContainer(hApp, (LPSTR)nameList, &nameListLen) != SAR_OK) {
		ERR_print_errors(bio_err);
		goto end;
	}

	for (name = nameList, i = 0; *name; name += strlen(name) + 1, i++) {
		ULONG containerType;
		LPSTR containerTypeName;

		if (SKF_OpenContainer(hApp, (LPSTR)name, &hContainer) != SAR_OK) {
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

		(void)BIO_printf(out, "  Container %d : %s (%s)\n",
			i, name, (char *)containerTypeName);
	}

	ret = 1;

end:
	if (hContainer && SKF_CloseContainer(hContainer) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_newcontainer(HAPPLICATION hApp, const char *name, const char *algor)
{
	int ret = 0;
	HCONTAINER hContainer = NULL;

	if (SKF_CreateContainer(hApp, (LPSTR)name, &hContainer) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	(void)BIO_printf(bio_err, "Container '%s' created\n", name);

	if (strcmp(algor, "SM2") == 0 || strcmp(algor, "sm2") == 0) {
		ECCPUBLICKEYBLOB publicKey = {0, {0}, {0}};
		if (SKF_GenECCKeyPair(hContainer, SGD_SM2_1, &publicKey) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}

		(void)BIO_printf(bio_err, "SM2 signing key pair generated\n");
		(void)BIO_printf(bio_err, "SM2 Signing Public Key:\n");
		if (SKF_PrintECCPublicKey(bio_err, &publicKey) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}

	} else if (strcmp(algor, "RSA") == 0 || strcmp(algor, "rsa")) {
		RSAPUBLICKEYBLOB publicKey = {0, 0, {0}, {0}};
		if (SKF_GenRSAKeyPair(hContainer, SGD_RSA, &publicKey) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}

		(void)BIO_printf(bio_err, "RSA signing key pair generated\n");
		(void)BIO_printf(bio_err, "RSA Signing Public Key:\n");
		if (SKF_PrintRSAPublicKey(bio_err, &publicKey) != SAR_OK) {
			ERR_print_errors(bio_err);
			goto end;
		}

	} else {
		(void)BIO_printf(bio_err, "Invalid container type\n");
		goto end;
	}

	ret = 1;

end:
	if (hContainer && SKF_CloseContainer(hContainer) != SAR_OK) {
		ERR_print_errors(bio_err);
		ret = 0;
	}
	return ret;
}

static int skf_delcontainer(HAPPLICATION hApp, const char *containername)
{
	if (SKF_DeleteContainer(hApp, (LPSTR)containername) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	return 1;
}

static int skf_importenckey(DEVHANDLE hDev, HCONTAINER hContainer, DEVINFO *devInfo,
	const char *infile, int informat, const char *passarg)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;

        if (!(pkey = load_key(infile, informat, 0, passarg, NULL, "Private Key"))) {
		BIO_printf(bio_err, "Error on reading private key\n");
		return 0;
	}
	if (SKF_ImportPrivateKey(hDev, hContainer, pkey, devInfo->DevAuthAlgId) != SAR_OK) {
		BIO_printf(bio_err, "Error on importing private key\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 1;
end:
	EVP_PKEY_free(pkey);
	return ret;
}

static int skf_exportkey(HCONTAINER hContainer, BOOL bSign, int outformat, BIO *out)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;

	if (SKF_ExportEVPPublicKey(hContainer, bSign, &pkey) != SAR_OK) {
		BIO_printf(bio_err, "Error on exporting public key\n");
		ERR_print_errors(bio_err);
		return 0;
	}

	if (outformat == FORMAT_ASN1)
		ret = i2d_PUBKEY_bio(out, pkey);
	else if (outformat == FORMAT_PEM)
		ret = PEM_write_bio_PUBKEY(out, pkey);
	else {
		BIO_printf(bio_err, "bad output format specified for outfile\n");
		goto end;
	}
	if (!ret) {
		BIO_printf(bio_err, "Unable to write certificate\n");
		ERR_print_errors(bio_err);
		goto end;
	}

end:
	EVP_PKEY_free(pkey);
	return ret;
}

static int skf_printkeys(HCONTAINER hContainer, BIO *out)
{
	int ret = 1;
	ULONG containerType;
	SKF_PUBLICKEYBLOB publicKey;
	ULONG len = sizeof(SKF_PUBLICKEYBLOB);

	if (SKF_GetContainerType(hContainer, &containerType) != SAR_OK) {
		ERR_print_errors(bio_err);
		return 0;
	}
	if (containerType == SKF_CONTAINER_TYPE_UNDEF) {
		BIO_printf(bio_err, "Container not initialized\n");
		return 0;
	}

	memset(&publicKey, 0, sizeof(publicKey));
	if (SKF_ExportPublicKey(hContainer, SGD_TRUE, (BYTE *)&publicKey, &len) == SAR_OK) {
		if (containerType == SKF_CONTAINER_TYPE_ECC) {
			BIO_puts(out, "SM2 signing public key:\n");
			if (SKF_PrintECCPublicKey(out,
				(ECCPUBLICKEYBLOB *)&publicKey) != SAR_OK) {
				ERR_print_errors(bio_err);
				ret = 0;
			}
		} else {
			BIO_puts(out, "RSA signing public key:\n");
			if (SKF_PrintRSAPublicKey(out,
				(RSAPUBLICKEYBLOB *)&publicKey) != SAR_OK) {
				ERR_print_errors(bio_err);
				ret = 0;
			}
		}
	} else {
		ERR_print_errors(bio_err);
		ret = 0;
	}

	memset(&publicKey, 0, sizeof(publicKey));
	if (SKF_ExportPublicKey(hContainer, SGD_FALSE, (BYTE *)&publicKey, &len) == SAR_OK) {
		if (containerType == SKF_CONTAINER_TYPE_ECC) {
			BIO_puts(out, "SM2 encryption public key:\n");
			if (SKF_PrintECCPublicKey(out,
				(ECCPUBLICKEYBLOB *)&publicKey) != SAR_OK) {
				ERR_print_errors(bio_err);
				ret = 0;
			}
		} else {
			BIO_puts(out, "RSA encryption public key:\n");
			if (SKF_PrintRSAPublicKey(out,
				(RSAPUBLICKEYBLOB *)&publicKey) != SAR_OK) {
				ERR_print_errors(bio_err);
				ret = 0;
			}
		}
	} else {
		ERR_print_errors(bio_err);
		ret = 0;
	}

	return ret;
}

static int skf_importcert(HCONTAINER hContainer, const char *infile, int informat)
{
	int ret = 0;
	X509 *x509 = NULL;

	if (!(x509 = load_cert(infile, informat, "Certificate"))) {
		BIO_printf(bio_err, "Load certificate failure\n");
		ERR_print_errors(bio_err);
		return 0;
	}
	if (SKF_ImportX509CertificateByKeyUsage(hContainer, x509) != SAR_OK) {
		BIO_printf(bio_err, "Error on importing certificate\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 1;

end:
	X509_free(x509);
	return ret;
}

static int skf_exportcert(HCONTAINER hContainer, BOOL bSign, int outform, BIO *out)
{
	int ret = 0;
	X509 *x509 = NULL;

	if (SKF_ExportX509Certificate(hContainer, bSign, &x509) != SAR_OK) {
		BIO_printf(bio_err, "Error on exporing certificate\n");
		ERR_print_errors(bio_err);
		return 0;
	}
	if (outform == FORMAT_ASN1)
		ret = i2d_X509_bio(out, x509);
	else if (outform == FORMAT_PEM)
		ret = PEM_write_bio_X509(out, x509);
	else {
		BIO_printf(bio_err, "bad output format specified for outfile\n");
		goto end;
	}
	if (!ret) {
		BIO_printf(bio_err, "Unable to write certificate\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 1;

end:
	X509_free(x509);
	return ret;
}

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
	char *passarg = NULL, *adminpassarg = NULL, *newpassarg = NULL;
	char *keypassarg = NULL;

	int op = OP_NONE;
	int admin = 0;
	char *algor = "SM2";

	char *transmit_cmd = NULL;

	DEVINFO devInfo = {{0,0}};
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
		case OPT_LISTDEVS:
			if (op)
				goto opthelp;
			op = OP_LISTDEVS;
			break;
		case OPT_DEV:
			devname = opt_arg();
			break;
		case OPT_DEVINFO:
			if (op)
				goto opthelp;
			op = OP_DEVINFO;
			break;
		case OPT_LABEL:
			if (op)
				goto opthelp;
			op = OP_LABEL;
			label = opt_arg();
			break;
		case OPT_AUTHKEY:
			authkey = opt_arg();
			break;
		case OPT_NEWAUTHKEY:
			if (op)
				goto opthelp;
			op = OP_NEWAUTHKEY;
			newauthkey = opt_arg();
			break;
		case OPT_TRANSMIT:
			if (op)
				goto opthelp;
			op = OP_TRANSMIT;
			transmit_cmd = opt_arg();
			break;
		case OPT_LISTAPPS:
			if (op)
				goto opthelp;
			op = OP_LISTAPPS;
			break;
		case OPT_NEWAPP:
			if (op)
				goto opthelp;
			op = OP_NEWAPP;
			appname = opt_arg();
			break;
		case OPT_DELAPP:
			if (op)
				goto opthelp;
			op = OP_DELAPP;
			appname = opt_arg();
			break;
		case OPT_APP:
			appname = opt_arg();
			break;
		case OPT_CHANGEPASS:
			if (op)
				goto opthelp;
			op = OP_CHANGEPASS;
			break;
		case OPT_PASS:
			passarg = opt_arg();
			break;
		case OPT_ADMIN:
			admin = 1;
			break;
		case OPT_ADMINPASS:
			adminpassarg = opt_arg();
			break;
		case OPT_NEWPASS:
			newpassarg = opt_arg();
			break;
		case OPT_UNBLOCK:
			if (op)
				goto opthelp;
			op = OP_UNBLOCK;
			break;
		case OPT_LISTOBJS:
			if (op)
				goto opthelp;
			op = OP_LISTOBJS;
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
		case OPT_OBJ:
			objname = opt_arg();
			break;
		case OPT_LISTCONTAINERS:
			if (op)
				goto opthelp;
			op = OP_LISTCONTAINERS;
			break;
		case OPT_NEWCONTAINER:
			if (op)
				goto opthelp;
			op = OP_NEWCONTAINER;
			containername = opt_arg();
			break;
		case OPT_ALGORITHM:
			algor = opt_arg();
			break;
		case OPT_DELCONTAINER:
			if (op)
				goto opthelp;
			op = OP_DELCONTAINER;
			containername = opt_arg();
			break;
		case OPT_CONTAINER:
			containername = opt_arg();
			break;
		case OPT_IMPORTENCKEY:
			if (op)
				goto opthelp;
			op = OP_IMPORTENCKEY;
			break;
		case OPT_KEYPASS:
			keypassarg = opt_arg();
			break;
		case OPT_EXPORTSIGNKEY:
			if (op)
				goto opthelp;
			op = OP_EXPORTSIGNKEY;
			break;
		case OPT_EXPORTENCKEY:
			if (op)
				goto opthelp;
			op = OP_EXPORTENCKEY;
			break;
		case OPT_PRINTKEYS:
			if (op)
				goto opthelp;
			op = OP_PRINTKEYS;
			break;
		case OPT_IMPORTCERT:
			if (op)
				goto opthelp;
			op = OP_IMPORTCERT;
			break;
		case OPT_EXPORTSIGNCERT:
			if (op)
				goto opthelp;
			op = OP_EXPORTSIGNCERT;
			break;
		case OPT_EXPORTENCCERT:
			if (op)
				goto opthelp;
			op = OP_EXPORTENCCERT;
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
	case OP_PRINTKEYS:
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

	switch (op) {
	case OP_DEVINFO:
		ret = skf_devinfo(devname, out);
		goto end;
	case OP_LABEL:
		ret = skf_label(devname, label);
		if (ret)
			BIO_printf(bio_err, "Device label changed to %s\n", label);
		goto end;
	case OP_TRANSMIT:
		ret = skf_transmit(devname, transmit_cmd, out);
		if (ret)
			BIO_printf(bio_err, "Tranmist finished\n");
		goto end;
	}

	/* opendev */
	if (!authkey) {
		BIO_printf(bio_err, "Authentication key not specified\n");
		goto opthelp;
	}
	if (!skf_opendev(devname, authkey, &devInfo, &hdev)) {
		goto end;
	}

	/* without appname */
	switch (op) {
	case OP_NEWAUTHKEY:
		ret = skf_newauthkey(hdev, newauthkey);
		if (ret)
			BIO_puts(bio_err, "Device authentication key changed\n");
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
		ret = skf_newapp(hdev, appname, passarg, adminpassarg);
		if (ret)
			BIO_printf(bio_err, "Application %s created\n", appname);
		goto end;
	case OP_DELAPP:
		ret = skf_delapp(hdev, appname);
		if (ret)
			BIO_printf(bio_err, "Application %s deleted\n", appname);
		goto end;
	case OP_CHANGEPASS:
		if (adminpassarg) {
			admin = 1;
			passarg = adminpassarg;
		}
		ret = skf_changepass(hdev, appname, admin, passarg, newpassarg);
		if (ret)
			BIO_printf(bio_err, "Application %s %s PIN changed\n",
				appname, admin ? "administrator" : "user");
		goto end;
	case OP_UNBLOCK:
		if (admin && passarg && !adminpassarg)
			adminpassarg = passarg;
		ret = skf_unblock(hdev, appname, adminpassarg, newpassarg);
		if (ret)
			BIO_printf(bio_err,
				"Application %s user PIN unblocked\n", appname);
		goto end;
	}

	/* open app */
	if (adminpassarg) {
		admin = 1;
		passarg = adminpassarg;
	}
	if (!skf_openapp(hdev, appname, admin, passarg,  &happ)) {
		goto end;
	}
	/*
	BIO_printf(bio_err, "Application %s opened by %s\n", appname,
		admin ? "administractor" : "user");
	*/

	switch (op) {
	case OP_LISTOBJS:
		BIO_printf(bio_err, "Application %s Objects:\n", appname);
		ret = skf_listobjs(happ, out);
		goto end;
	case OP_LISTCONTAINERS:
		BIO_printf(bio_err, "Application %s Containers:\n", appname);
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
		if (ret)
			BIO_printf(bio_err, "Object %s imported\n", objname);
		goto end;
	case OP_EXPORTOBJ:
		ret = skf_exportobj(happ, objname, out);
		if (ret)
			BIO_printf(bio_err, "Object %s exported\n", objname);
		goto end;
	case OP_DELOBJ:
		ret = skf_delobj(happ, objname);
		if (ret)
			BIO_printf(bio_err, "Object %s deleted\n", objname);
		goto end;
	}

	if (!containername) {
		BIO_printf(bio_err, "No container name is given\n");
		goto opthelp;
	}
	switch (op) {
	case OP_NEWCONTAINER:
		ret = skf_newcontainer(happ, containername, algor);
		if (ret)
			BIO_printf(bio_err, "Container %s created\n", containername);
		goto end;
	case OP_DELCONTAINER:
		ret = skf_delcontainer(happ, containername);
		if (ret)
			BIO_printf(bio_err, "Container %s deleted\n", containername);
		goto end;
	}

	if (SKF_OpenContainer(happ, (LPSTR)containername, &hcontainer) != SAR_OK) {
		BIO_printf(bio_err, "Error on open container %s\n", containername);
		ERR_print_errors(bio_err);
		goto end;
	}
	switch (op) {
	case OP_IMPORTENCKEY:
		ret = skf_importenckey(hdev, hcontainer, &devInfo, infile, informat, keypassarg);
		if (ret)
			BIO_printf(bio_err, "Private key imported to container %s\n", containername);
		break;
	case OP_EXPORTSIGNKEY:
		ret = skf_exportkey(hcontainer, SGD_TRUE, outformat, out);
		break;
	case OP_EXPORTENCKEY:
		ret = skf_exportkey(hcontainer, SGD_FALSE, outformat, out);
		break;
	case OP_PRINTKEYS:
		ret = skf_printkeys(hcontainer, out);
		break;
	case OP_IMPORTCERT:
		ret = skf_importcert(hcontainer, infile, informat);
		if (ret)
			BIO_printf(bio_err, "Certificate imported to container %s\n", containername);
		break;
	case OP_EXPORTSIGNCERT:
		ret = skf_exportcert(hcontainer, SGD_TRUE, outformat, out);
		break;
	case OP_EXPORTENCCERT:
		ret = skf_exportcert(hcontainer, SGD_FALSE, outformat, out);
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
#endif
