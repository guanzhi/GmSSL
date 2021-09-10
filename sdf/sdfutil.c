/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */


# include <stdio.h>
# include <stdlib.h>
# include <string.h>
#include "sdf.h"
#include "sdf_ext.h"


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


void print_usage(FILE *out, const char *prog)
{
	fprintf(out, "Usage: %s commands\n", prog);
	fprintf(out, "\n");
	fprintf(out, "Commands:\n");
	fprintf(out, "  -help           print the usage message\n");
	fprintf(out, "  -lib            Vendor's SDF dynamic library\n");
	fprintf(out, "  -vendor         Vendor name\n");
	fprintf(out, "  -printdevinfo   Print device information\n");
	fprintf(out, "  -printsm2sign   Print SM2 signing key with key index\n");
	fprintf(out, "  -printsm2enc    Print SM2 encryption key with key index\n");
	fprintf(out, "  -printrsasign   Print RSA signing key with key index\n");
	fprintf(out, "  -printrsaenc    Print RSA encryption key with key index\n");
	fprintf(out, "  -accesskey      Access private key with the key index number\n");
	fprintf(out, "  -pass           Passphrase source for accessing private key\n");
	fprintf(out, "  -importobj      Import data object into device\n");
	fprintf(out, "  -exportobj      Export data object from device\n");
	fprintf(out, "  -delobj         Delete data object from device\n");
	fprintf(out, "  -in             File to be imported from\n");
	fprintf(out, "  -out            File to be exported to\n");

}

int main(int argc, char **argv)
{
	int ret = 1;
	char *infile = NULL, *outfile = NULL, *prog;
	char *objname = NULL, *passarg = NULL, *pass = NULL;
	FILE *in = NULL, *out = NULL;
	char *lib = NULL, *vendor = NULL;
	unsigned char buf[SDF_MAX_FILE_SIZE];
	unsigned int ulen;
	int len, key_idx = -1;

	int o;
	int op = OP_NONE;
	void *hDev = NULL;
	void *hSession = NULL;

	argc--;
	argv++;
	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
opthelp:
			print_usage(stdout, prog);
			goto end;

		} else if (!strcmp(*argv, "-lib")) {
			if (--argc < 1) goto bad;
			lib = *(++argv);

		} else if (!strcmp(*argv, "-vendor")) {
			if (--argc < 1) goto bad;
			vendor = *(++argv);

		} else if (!strcmp(*argv, "-printdevinfo")) {
			if (op)
				goto opthelp;
			op = OP_PRINTDEVINFO;
			if (--argc < 1) goto bad;
			key_idx = atoi(*(++argv));

		} else if (!strcmp(*argv, "-printsm2sign")) {
			if (op)
				goto opthelp;
			op = OP_PRINTSM2SIGN;
			if (--argc < 1) goto bad;
			key_idx = atoi(*(++argv));

		} else if (!strcmp(*argv, "-printsm2enc")) {
			if (op)
				goto opthelp;
			op = OP_PRINTSM2ENC;
			if (--argc < 1) goto bad;
			key_idx = atoi(*(++argv));

		} else if (!strcmp(*argv, "-printrsasign")) {
			if (op)
				goto opthelp;
			op = OP_PRINTRSASIGN;
			if (--argc < 1) goto bad;
			key_idx = atoi(*(++argv));

		} else if (!strcmp(*argv, "-printrsaenc")) {
			if (op)
				goto opthelp;
			op = OP_PRINTRSAENC;
			if (--argc < 1) goto bad;
			key_idx = atoi(*(++argv));

		} else if (!strcmp(*argv, "-accesskey")) {
			if (--argc < 1) goto bad;
			key_idx = atoi(*(++argv));

		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);

		} else if (!strcmp(*argv, "-importobj")) {
			if (op)
				goto opthelp;
			op = OP_IMPORTOBJ;
			if (--argc < 1) goto bad;
			objname = *(++argv);

		} else if (!strcmp(*argv, "-exportobj")) {
			if (op)
				goto opthelp;
			op = OP_EXPORTOBJ;
			if (--argc < 1) goto bad;
			objname = *(++argv);

		} else if (!strcmp(*argv, "-delobj")) {
			if (op)
				goto opthelp;
			op = OP_DELOBJ;
			if (--argc < 1) goto bad;
			objname = *(++argv);

		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);

		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);

		} else {
			break;
		}

		argc--;
		argv++;
	}


	if (argc != 0)
		goto opthelp;

	if (!lib) {
		fprintf(stderr, "Option '-lib' required\n");
		goto opthelp;
	}
	if (SDF_LoadLibrary(lib, vendor) != SDR_OK) {
		//ERR_print_errors(stderr);
		goto end;
	}

	if (op == OP_NONE) {
		ret = 0;
		goto end;
	}

	if (SDF_OpenDevice(&hDev) != SDR_OK
		|| SDF_OpenSession(hDev, &hSession) != SDR_OK) {
		//ERR_print_errors(stderr);
		goto end;
	}

	switch (op) {
	case OP_PRINTDEVINFO:
	case OP_PRINTSM2SIGN:
	case OP_PRINTSM2ENC:
	case OP_PRINTRSASIGN:
	case OP_PRINTRSAENC:
		if (!(out = fopen(outfile, "w"))) {
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
			fprintf(stderr, "Invalid key index\n");
			goto end;
		}
		break;
	}

	if (op == OP_PRINTDEVINFO) {
		DEVICEINFO devInfo;
		if (SDF_GetDeviceInfo(hSession, &devInfo) != SDR_OK
			|| SDF_PrintDeviceInfo(out, &devInfo) != SDR_OK) {
			//ERR_print_errors(stderr);
			goto end;
		}

	} else if (op == OP_PRINTSM2SIGN || op == OP_PRINTSM2ENC) {
		ECCrefPublicKey publicKey;
		if (op == OP_PRINTSM2SIGN) {
			if (SDF_ExportSignPublicKey_ECC(hSession,
				key_idx, &publicKey) != SDR_OK) {
				//ERR_print_errors(stderr);
				goto end;
			}
			fprintf(out, "SM2 Signing Public Key:\n");
		} else {
			if (SDF_ExportEncPublicKey_ECC(hSession,
				key_idx, &publicKey) != SDR_OK) {
				//ERR_print_errors(stderr);
				goto end;
			}
			fprintf(out, "SM2 Encryption Public Key:\n");
		}
		if (SDF_PrintECCPublicKey(out, &publicKey) != SDR_OK) {
			//ERR_print_errors(stderr);
			goto end;
		}

	} else if (op == OP_PRINTRSASIGN || op == OP_PRINTRSAENC) {
		RSArefPublicKey publicKey;
		if (op == OP_PRINTRSASIGN) {
			if (SDF_ExportSignPublicKey_RSA(hSession,
				key_idx, &publicKey) != SDR_OK) {
				//ERR_print_errors(stderr);
				goto end;
			}
			fprintf(out, "RSA Signing Public Key:\n");
		} else {
			if (SDF_ExportEncPublicKey_RSA(hSession,
				key_idx, &publicKey) != SDR_OK) {
				//ERR_print_errors(stderr);
				goto end;
			}
			fprintf(out, "RSA Encryption Public Key:\n");
		}
		if (SDF_PrintRSAPublicKey(out, &publicKey) != SDR_OK) {
			//ERR_print_errors(stderr);
			goto end;
		}

	} else if (op == OP_ACCESSKEY) {
		if (SDF_GetPrivateKeyAccessRight(hSession, (unsigned int)key_idx,
			(unsigned char *)pass, strlen(pass)) != SDR_OK) {
			return 0;
		}
		(void)SDF_ReleasePrivateKeyAccessRight(hSession, (unsigned int)key_idx);
		fprintf(stderr, "Access private key %d success\n", key_idx);

	} else if (op == OP_IMPORTOBJ) {
		if (!(in = fopen(infile, "r"))) {
			goto opthelp;
		}
		if ((len = fread(buf, 1, SDF_MAX_FILE_SIZE, in)) < 0) {
			fprintf(stderr, "Error reading data object content\n");
			goto end;
		}
		if (SDF_CreateFile(hSession, (unsigned char *)objname, strlen(objname), len) != SDR_OK
			|| SDF_WriteFile(hSession, (unsigned char *)objname, strlen(objname), 0, len, buf) != SDR_OK) {
			//ERR_print_errors(stderr);
			goto end;
		}
		fprintf(stderr, "Object '%s' (%d bytes) created\n", objname, len);

	} else if (op == OP_EXPORTOBJ) {
		if (!(out = fopen(outfile, "w"))) {
			goto opthelp;
		}
		if (SDF_ReadFile(hSession, (unsigned char *)objname, strlen(objname), 0, &ulen, buf) != SDR_OK
			|| fwrite(buf, 1, ulen, out) != ulen) {
			//ERR_print_errors(stderr);
			goto end;
		}
		fprintf(stderr, "Object '%s' (%u bytes) exported\n", objname, ulen);

	} else if (op == OP_DELOBJ) {
		if (SDF_DeleteFile(hSession, (unsigned char *)objname, strlen(objname)) != SDR_OK) {
			//ERR_print_errors(stderr);
			goto end;
		}
		fprintf(stderr, "Object '%s' deleted\n", objname);

	} else {
		goto end;
	}

	ret = 0;

bad:
	fprintf(stderr, "%s: commands should not be used together\n", prog);


end:
	fclose(in);
	fclose(out);

	if (hSession) (void)SDF_CloseSession(hSession);
	if (hDev) (void)SDF_CloseDevice(hDev);
	if (lib) SDF_UnloadLibrary();
	return ret;
}
