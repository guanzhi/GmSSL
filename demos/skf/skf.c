#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
/*
 * When USE_GMAPI, the code need to load vendor's SKF dynamic library through
 * the GmSSL SKF framework, and the error string can be printed through the ERR
 * module.
 */
#ifdef USE_GMAPI
# include <openssl/err.h>
# include <openssl/gmskf.h>
# include <openssl/is_gmssl.h>
#else
/*
 * Else the code can be directly linked with vendor's static or dynamic SKF
 * library, and the code also need the vendor's SKF header files.
 */
# include "skf.h"
#endif

int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = basename(argv[0]);
	ULONG rv;
	LPSTR nameList = NULL;
	ULONG ulSize;
	DEVHANDLE hDev;
	DEVINFO devInfo;

#ifdef USE_GMAPI
	if (argc != 2) {
		printf("usage: %s <libskf.so>\n", prog);
		return -1;
	}

	if ((rv = SKF_LoadLibrary((LPSTR)argv[1], NULL)) != SAR_OK) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
#endif

	if ((rv = SKF_EnumDev(TRUE, NULL, &ulSize)) != SAR_OK) {
		fprintf(stderr, "%s: SKF_EnumDev() return %u\n", prog, rv);
		goto end;
	}

	if (!(nameList = malloc(ulSize))) {
		goto end;
	}

	if ((rv = SKF_EnumDev(TRUE, nameList, &ulSize)) != SAR_OK) {
		fprintf(stderr, "%s: SKF_EnumDev() return %u\n", prog, rv);
		goto end;
	}

	if ((rv = SKF_ConnectDev(nameList, &hDev)) != SAR_OK) {
		fprintf(stderr, "%s: SKF_EnumDev() return %u\n", prog, rv);
		goto end;
	}

	if ((rv = SKF_GetDevInfo(hDev, &devInfo)) != SAR_OK) {
		fprintf(stderr, "%s: SKF_EnumDev() return %u\n", prog, rv);
		goto end;
	}

#ifdef USE_GMAPI
	if ((rv = SKF_PrintDevInfo(&devInfo)) != SAR_OK) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
#endif

	if ((rv = SKF_DisConnectDev(hDev)) != SAR_OK) {
		fprintf(stderr, "%s: SKF_EnumDev() return %u\n", prog, rv);
		goto end;
	}

	ret = 0;

end:
#ifdef USE_GMAPI
	SKF_UnloadLibrary();
#endif
	free(nameList);
	return ret;
}
