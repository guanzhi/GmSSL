#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#ifdef USE_GMAPI
# include <openssl/err.h>
# include <openssl/gmsdf.h>
# include <openssl/is_gmssl.h>
#else
/*
 * We need vendor's SDF dynamic library and headers, for example when using
 * Sansec PCI-E SDF card, make the following link:
 * `ln -s /path/to/sansec/lib/linux/x86_64/libswsds.so.4.6.2.0_x64 libsdf.so`
 * `ln -s /path/to/sansec/include/swsds.h sdf.h`
 */
# include "sdf.h"
#endif


int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = basename(argv[0]);
	int rv;
	void *hDev = NULL;
	void *hSession = NULL;
	DEVICEINFO devInfo;

#ifdef USE_GMAPI
	if (argc != 2) {
		printf("usage: %s <libsdf.so>\n", prog);
		return -1;
	}

	if ((rv = SDF_LoadLibrary(argv[1], NULL)) != SDR_OK) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
#endif

	if ((rv = SDF_OpenDevice(&hDev)) != SDR_OK) {
		fprintf(stderr, "%s: SDF_OpenDevice() return %08X", prog, rv);
		goto end;
	}

	if ((rv = SDF_OpenSession(hDev, &hSession)) != SDR_OK) {
		fprintf(stderr, "%s: SDF_OpenSession() return %08X", prog, rv);
		goto end;
	}

	if ((rv = SDF_GetDeviceInfo(hSession, &devInfo)) != SDR_OK) {
		fprintf(stderr, "%s: SDF_GetDeviceInfo() return %08X", prog, rv);
		goto end;
	}

#ifdef USE_GMAPI
	if ((rv = SDF_PrintDeviceInfo(&devInfo)) != SDR_OK) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
#endif

	if ((rv = SDF_CloseSession(hSession)) != SDR_OK) {
		fprintf(stderr, "%s: SDF_CloseSession() return %08X", prog, rv);
		goto end;
	}

	if ((rv = SDF_CloseDevice(hDev)) != SDR_OK) {
		fprintf(stderr, "%s: SDF_CloseDevice() return %08X", prog, rv);
		goto end;
	}

	ret = 0;

end:
#ifdef USE_GMAPI
	if (rv != SDR_OK) {
		char *errstr;
		SDF_GetErrorString(rv, &errstr);
		fprintf(stderr, "%s: %s\n", prog, errstr);
		ERR_print_errors_fp(stderr);
	}

	SDF_UnloadLibrary();
#endif
	return ret;
}
