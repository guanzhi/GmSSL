/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/hex.h>
#include <gmssl/error.h>


static const char *pem_unix_style =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG\n"
	"EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw\n"
	"MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO\n"
	"UkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE\n"
	"MPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRT\n"
	"V7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti\n"
	"W/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZ\n"
	"MxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b\n"
	"53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI\n"
	"pDoiVhsLwg==\n"
	"-----END CERTIFICATE-----\n";

static const char *pem_windows_style =
	"-----BEGIN CERTIFICATE-----\r\n"
	"MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG\r\n"
	"EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw\r\n"
	"MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO\r\n"
	"UkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE\r\n"
	"MPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRT\r\n"
	"V7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti\r\n"
	"W/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZ\r\n"
	"MxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b\r\n"
	"53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI\r\n"
	"pDoiVhsLwg==\r\n"
	"-----END CERTIFICATE-----\r\n";

#define TEST_PEM_BASE64_DECODE 1

static const char *pem_bin_hex =
	"308201B330820157A003020102020869E2FEC0170AC67B300C06082A811CCF550183750500302E310B30090603550406"
	"1302434E310E300C060355040A0C054E52434143310F300D06035504030C06524F4F544341301E170D31323037313430"
	"33313135395A170D3432303730373033313135395A302E310B300906035504061302434E310E300C060355040A0C054E"
	"52434143310F300D06035504030C06524F4F5443413059301306072A8648CE3D020106082A811CCF5501822D03420004"
	"30F09C6BAA6681C721B137F652705E2FDAEDA789F0FA2B64D4ACEB99B9EAA34E655309309562BEE0E22BB45740AA7453"
	"57B43DBF586D92FE364EC22EB73775DBA35D305B301F0603551D230418301680144C32B197D9331BC4A605C1C6E58B62"
	"5BF0977658300C0603551D13040530030101FF300B0603551D0F040403020106301D0603551D0E041604144C32B197D9"
	"331BC4A605C1C6E58B625BF0977658300C06082A811CCF550183750500034800304502201B56D22DE397A77A01F07EDB"
	"E775BE08A38F9763E49E6584ABF94C86D9F6E479022100DA1C3816C5616D9C2AC18C7D7AFD6DC4CE7EFF53F563A39C48"
	"A43A22561B0BC2";


static int test_pem_unix_style(void)
{
	FILE *fp;
	const char *text = pem_unix_style;
	size_t textlen = strlen(text);
	const char *file = "test_unix_style.pem";
	uint8_t buf[1024];
	size_t len;

	if (!(fp = fopen(file, "wb"))) {
		error_print();
		return -1;
	}
	fwrite(text, 1, textlen, fp);
	fclose(fp);

	if (!(fp = fopen(file, "rb"))) {
		error_print();
		return -1;
	}
	if (pem_read(fp, "CERTIFICATE", buf, &len, sizeof(buf)) != 1) {
		error_print();
		return -1;
	}
	fclose(fp);

	if (TEST_PEM_BASE64_DECODE) {
		uint8_t bin[1024];
		size_t binlen;
		hex_to_bytes(pem_bin_hex, strlen(pem_bin_hex), bin, &binlen);
		if (len != binlen) {
			error_print();
			return -1;
		}
		if (memcmp(buf, bin, binlen) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_pem_unix_style_without_last_newline(void)
{
	FILE *fp;
	const char *text = pem_unix_style;
	size_t textlen = strlen(text) - 1; // without last '\n'
	const char *file = "test_unix_style_without_last_newline.pem";
	uint8_t buf[1024];
	size_t len;

	if (!(fp = fopen(file, "wb"))) {
		error_print();
		return -1;
	}
	fwrite(text, 1, textlen, fp);
	fclose(fp);

	if (!(fp = fopen(file, "rb"))) {
		error_print();
		return -1;
	}
	if (pem_read(fp, "CERTIFICATE", buf, &len, sizeof(buf)) != 1) {
		error_print();
		return -1;
	}
	fclose(fp);

	if (TEST_PEM_BASE64_DECODE) {
		uint8_t bin[1024];
		size_t binlen;
		hex_to_bytes(pem_bin_hex, strlen(pem_bin_hex), bin, &binlen);
		if (len != binlen) {
			error_print();
			return -1;
		}
		if (memcmp(buf, bin, binlen) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_pem_windows_style(void)
{
	FILE *fp;
	const char *text = pem_windows_style;
	size_t textlen = strlen(text);
	const char *file = "test_windows_style.pem";
	uint8_t buf[1024];
	size_t len;

	if (!(fp = fopen(file, "wb"))) {
		error_print();
		return -1;
	}
	fwrite(text, 1, textlen, fp);
	fclose(fp);

	if (!(fp = fopen(file, "rb"))) {
		error_print();
		return -1;
	}
	if (pem_read(fp, "CERTIFICATE", buf, &len, sizeof(buf)) != 1) {
		error_print();
		return -1;
	}
	fclose(fp);

	if (TEST_PEM_BASE64_DECODE) {
		uint8_t bin[1024];
		size_t binlen;
		hex_to_bytes(pem_bin_hex, strlen(pem_bin_hex), bin, &binlen);
		if (len != binlen) {
			error_print();
			return -1;
		}
		if (memcmp(buf, bin, binlen) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_pem_windows_style_without_last_newline(void)
{
	FILE *fp;
	const char *text = pem_windows_style;
	size_t textlen = strlen(text) - 2; // without last '\r\n'
	const char *file = "test_windows_style_without_last_newline.pem";
	uint8_t buf[1024];
	size_t len;

	if (!(fp = fopen(file, "wb"))) {
		error_print();
		return -1;
	}
	fwrite(text, 1, textlen, fp);
	fclose(fp);

	if (!(fp = fopen(file, "rb"))) {
		error_print();
		return -1;
	}
	if (pem_read(fp, "CERTIFICATE", buf, &len, sizeof(buf)) != 1) {
		error_print();
		return -1;
	}
	fclose(fp);

	if (TEST_PEM_BASE64_DECODE) {
		uint8_t bin[1024];
		size_t binlen;
		hex_to_bytes(pem_bin_hex, strlen(pem_bin_hex), bin, &binlen);
		if (len != binlen) {
			error_print();
			return -1;
		}
		if (memcmp(buf, bin, binlen) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_pem_unix_style() != 1) { error_print(); return 1; }
	if (test_pem_unix_style_without_last_newline() != 1) { error_print(); return 1; }
	if (test_pem_windows_style() != 1) { error_print(); return 1; }
	if (test_pem_windows_style_without_last_newline() != 1) { error_print(); return 1; }
	return 0;
}
