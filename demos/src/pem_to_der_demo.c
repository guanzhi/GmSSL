/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/pem.h>


char *pem =
"-----BEGIN X509 CRL-----\n"
"MIIECTCCA7ACAQEwCgYIKoEcz1UBg3UwLjELMAkGA1UEBhMCQ04xDjAMBgNVBAoM\n"
"BU5SQ0FDMQ8wDQYDVQQDDAZST09UQ0EXDTIyMDUwNTA2MjA1NFoXDTIyMDYwNDA2\n"
"MjA1NFowggMeMCECEBLy0JMksKPrcTKqfySoFJoXDTE0MDYyNjA2NTg0OFowLwIQ\n"
"F1kfbiJLPrYKNdxIJ4w3dBcNMjIwMzEwMDcyNjQ2WjAMMAoGA1UdFQQDCgEFMC8C\n"
"ECFrvrdMAraAJKDtcOipJYwXDTE0MDMxMTAyMTg0N1owDDAKBgNVHRUEAwoBBDAv\n"
"AhAso1+i8GB5G7HzfbZcHHcfFw0xODA1MjgwNjUwNDhaMAwwCgYDVR0VBAMKAQQw\n"
"IQIQLn+JRWnObfUtfuKEZ9Lk3xcNMTUwNzEwMDYxNjQzWjAvAhAxvIFAnIk1ExQi\n"
"lLa7ly7fFw0yMjAxMjAwMjA5MDdaMAwwCgYDVR0VBAMKAQQwIQIQQqrFI2ti9gJv\n"
"R+/UiRR1JxcNMTIxMDEzMDcyNDAxWjAvAhBKpT8UZ3DKn5ichVUzLHmSFw0yMjA0\n"
"MTIwNzIyMDBaMAwwCgYDVR0VBAMKAQQwIQIQTA8W7aoTN7SIsvYOQ0poFxcNMTMw\n"
"NjA0MDI0NTE5WjAvAhBS4bt9Xx8gOQPBXMoaTIN2Fw0xODA2MDUwMjI3NTlaMAww\n"
"CgYDVR0VBAMKAQQwLwIQXBWKTL8V1+4VQK3OAQh5MhcNMTgxMTA5MDIwODIyWjAM\n"
"MAoGA1UdFQQDCgEEMC8CEGZfiLjdS1X6fQRRHPAauhcXDTIyMDQyMTA4MDE0NFow\n"
"DDAKBgNVHRUEAwoBBDAvAhBpcFgVqJNeVhh23eFdcZgpFw0yMDEwMjkwMDE2MTBa\n"
"MAwwCgYDVR0VBAMKAQQwLwIQbWKZC2NJ54Xmslv2US6JzRcNMjIwMjI4MDcxNjQ1\n"
"WjAMMAoGA1UdFQQDCgEEMCECEG5dcs6A3HJWRbdM6qfIhcEXDTEyMTAxMzA4NDgy\n"
"M1owLwIQdllAJgu01vXbP+itlVhrHxcNMjExMjA4MTAyNDU1WjAMMAoGA1UdFQQD\n"
"CgEFMC8CEHkcLTgVjYirAEsAkdoukH4XDTIyMDQyMDA4MjY0NVowDDAKBgNVHRUE\n"
"AwoBBDAhAhB+FeffIjmW8i3UZgWnaK33Fw0xMjEwMTMwODQ3NDhaoC8wLTAfBgNV\n"
"HSMEGDAWgBRMMrGX2TMbxKYFwcbli2Jb8Jd2WDAKBgNVHRQEAwIBADAKBggqgRzP\n"
"VQGDdQNHADBEAiA8hM9ChjDbxNQnuZzb3z2oOaEl8Yn253Uj9F+vMY02ZgIgOiJ5\n"
"0n9tbpYQhrzheJMz3e9r/AjmDxZLyatOkMD31MI=\n"
"-----END X509 CRL-----\n";

static int prepare_pem_file(void)
{
	FILE *fp;

	if (!(fp = fopen("crl.pem", "wb"))) {
		fprintf(stderr, "fopen() error\n");
		return -1;
	}

	if (fwrite(pem, 1, strlen(pem), fp) != strlen(pem)) {
		fprintf(stderr, "fwrite() error\n");
		return -1;
	}

	fclose(fp);
	return 1;
}

int main(int argc, char **argv)
{
	int ret = -1;
	FILE *fp = NULL;
	uint8_t buf[4096];
	size_t len;
	size_t i;

	(void)prepare_pem_file();

	if (!(fp = fopen("crl.pem", "rb"))) {
		fprintf(stderr, "open crl.pem error\n");
		goto err;
	}

	if (pem_read(fp, "X509 CRL", buf, &len, sizeof(buf)) != 1) {
		fprintf(stderr, "pem_read() error\n");
		goto err;
	}

	printf("uint8_t crl_der[] = {");
	for (i = 0; i < len; i++) {
		if (i % 16 == 0) printf("\n");
		printf("0x%02x,", buf[i]);
	}
	printf("};\n");

	ret = 0;
err:
	fclose(fp);
	return ret;
}
