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
#include <gmssl/x509_cer.h>

char *pem =
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

static int prepare_pem_file(void)
{
	FILE *fp;

	if (!(fp = fopen("cert.pem", "wb"))) {
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
	uint8_t cert[2048];
	size_t certlen;
	const uint8_t *serial;
	size_t serial_len;
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *subject;
	size_t subject_len;
	SM2_KEY subject_public_key;
	size_t i;

	(void)prepare_pem_file();

	if (!(fp = fopen("cert.pem", "rb"))) {
		fprintf(stderr, "fopen() cert.pem error\n");
		goto err;
	}

	if (x509_cert_from_pem(cert, &certlen, sizeof(cert), fp) != 1) {
		fprintf(stderr, "x509_cert_from_pem() error\n");
		goto err;
	}

	if (x509_cert_get_issuer_and_serial_number(cert, certlen, &issuer, &issuer_len, &serial, &serial_len) != 1)
		goto err;
	if (x509_cert_get_subject(cert, certlen, &subject, &subject_len) != 1)
		goto err;
	if (x509_cert_get_subject_public_key(cert, certlen, &subject_public_key) != 1)
		goto err;

	if (x509_name_equ(subject, subject_len, issuer, issuer_len) == 1) {
		printf("This is self-signed certificate\n");
	}

	printf("SerialNumber: ");
	for (i = 0; i < serial_len; i++) {
		printf("%02X", serial[i]);
	}
	printf("\n");

	x509_name_print(stdout, 0, 0, "Issuer", issuer, issuer_len);
	x509_name_print(stdout, 0, 0, "Subject", subject, subject_len);
	sm2_public_key_print(stdout, 0, 0, "SubjectPublicKey", &subject_public_key);

	ret = 0;
err:
	if (fp) fclose(fp);
	return ret;
}
