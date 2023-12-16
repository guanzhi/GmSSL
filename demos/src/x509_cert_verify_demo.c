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

char *signcert_pem =
"-----BEGIN CERTIFICATE-----\n"
"MIICzzCCAnKgAwIBAgIFEzY5M3AwDAYIKoEcz1UBg3UFADAlMQswCQYDVQQGEwJD\n"
"TjEWMBQGA1UECgwNQ0ZDQSBTTTIgT0NBMTAeFw0yMTA2MTEwOTA1MjBaFw0yNjA2\n"
"MTkwODE2NTZaMIGRMQswCQYDVQQGEwJDTjEPMA0GA1UECAwG5YyX5LqsMQ8wDQYD\n"
"VQQHDAbljJfkuqwxJzAlBgNVBAoMHuS4reWbvemTtuihjOiCoeS7veaciemZkOWF\n"
"rOWPuDERMA8GA1UECwwITG9jYWwgUkExDDAKBgNVBAsMA1NTTDEWMBQGA1UEAwwN\n"
"ZWJzc2VjLmJvYy5jbjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABPsNUnoZQM9C\n"
"SnvC57TbvdfyOTCuPOSlZmPAyxBKFj+Y1QH/xlubHdVf5XqHrO1jCDRi7aN5IKGX\n"
"QF1492c803OjggEeMIIBGjAfBgNVHSMEGDAWgBRck1ggWiRzVhAbZFAQ7OmnygdB\n"
"ETAMBgNVHRMBAf8EAjAAMEgGA1UdIARBMD8wPQYIYIEchu8qAQEwMTAvBggrBgEF\n"
"BQcCARYjaHR0cDovL3d3dy5jZmNhLmNvbS5jbi91cy91cy0xNC5odG0wNwYDVR0f\n"
"BDAwLjAsoCqgKIYmaHR0cDovL2NybC5jZmNhLmNvbS5jbi9TTTIvY3JsNTYxOC5j\n"
"cmwwGAYDVR0RBBEwD4INZWJzc2VjLmJvYy5jbjAOBgNVHQ8BAf8EBAMCBsAwHQYD\n"
"VR0OBBYEFJ6oFo/OrKgDhHFORpaq04kX7T1KMB0GA1UdJQQWMBQGCCsGAQUFBwMC\n"
"BggrBgEFBQcDATAMBggqgRzPVQGDdQUAA0kAMEYCIQCvhSvbv5h6ERl1YcCLg+fz\n"
"9UleQbaPfBYwUjUD2dAHVQIhAMRC4k9S/mSC0UpUvCqh/DQC2Ui8Tccd5G2IgYSs\n"
"cnUN\n"
"-----END CERTIFICATE-----\n";

char *enccert_pem =
"-----BEGIN CERTIFICATE-----\n"
"MIICzjCCAnKgAwIBAgIFEzY5M3EwDAYIKoEcz1UBg3UFADAlMQswCQYDVQQGEwJD\n"
"TjEWMBQGA1UECgwNQ0ZDQSBTTTIgT0NBMTAeFw0yMTA2MTEwOTA1MjBaFw0yNjA2\n"
"MTkwODE2NTZaMIGRMQswCQYDVQQGEwJDTjEPMA0GA1UECAwG5YyX5LqsMQ8wDQYD\n"
"VQQHDAbljJfkuqwxJzAlBgNVBAoMHuS4reWbvemTtuihjOiCoeS7veaciemZkOWF\n"
"rOWPuDERMA8GA1UECwwITG9jYWwgUkExDDAKBgNVBAsMA1NTTDEWMBQGA1UEAwwN\n"
"ZWJzc2VjLmJvYy5jbjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABMn1q+hbV0i1\n"
"qnKAy7QeZ3ZfAD+gqHX4F5MqIhsarODlWsavf/dcprC0F277zc44aYBB/3ucy4PF\n"
"qXaRHQp8PEyjggEeMIIBGjAfBgNVHSMEGDAWgBRck1ggWiRzVhAbZFAQ7OmnygdB\n"
"ETAMBgNVHRMBAf8EAjAAMEgGA1UdIARBMD8wPQYIYIEchu8qAQEwMTAvBggrBgEF\n"
"BQcCARYjaHR0cDovL3d3dy5jZmNhLmNvbS5jbi91cy91cy0xNC5odG0wNwYDVR0f\n"
"BDAwLjAsoCqgKIYmaHR0cDovL2NybC5jZmNhLmNvbS5jbi9TTTIvY3JsNTYxOC5j\n"
"cmwwGAYDVR0RBBEwD4INZWJzc2VjLmJvYy5jbjAOBgNVHQ8BAf8EBAMCAzgwHQYD\n"
"VR0OBBYEFF/a1JHvzLzbpFbBljX7hNxRpj/2MB0GA1UdJQQWMBQGCCsGAQUFBwMC\n"
"BggrBgEFBQcDATAMBggqgRzPVQGDdQUAA0gAMEUCIQDCOFi1eZcgiN6t+h6lxLwS\n"
"grAh3Jall+ZyA2ePw6xcjwIgNyDvo761dpwJhcyWfyVCAnaTf0Vf4DLWI1K+S7po\n"
"Ur8=\n"
"-----END CERTIFICATE-----\n";


char *cacert_pem =
"-----BEGIN CERTIFICATE-----\n"
"MIICNTCCAdmgAwIBAgIFEAAAAAgwDAYIKoEcz1UBg3UFADBYMQswCQYDVQQGEwJD\n"
"TjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9y\n"
"aXR5MRcwFQYDVQQDDA5DRkNBIENTIFNNMiBDQTAeFw0xMzAxMjQwODQ2NDBaFw0z\n"
"MzAxMTkwODQ2NDBaMCUxCzAJBgNVBAYTAkNOMRYwFAYDVQQKDA1DRkNBIFNNMiBP\n"
"Q0ExMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEfJqQoo0+JoyCRy0msS2Ym076\n"
"8nV1pSLuK9utS1ij38obWDymq0oMRRwUzDMEQI19Cajo3JUoGFxOvsA+YWu3XKOB\n"
"wDCBvTAfBgNVHSMEGDAWgBTkjt3Uo+e2D+4dJ5bNddwlJXJp3TAMBgNVHRMEBTAD\n"
"AQH/MGAGA1UdHwRZMFcwVaBToFGkTzBNMQswCQYDVQQGEwJDTjETMBEGA1UECgwK\n"
"Q0ZDQSBDUyBDQTEMMAoGA1UECwwDQ1JMMQwwCgYDVQQLDANTTTIxDTALBgNVBAMM\n"
"BGNybDEwCwYDVR0PBAQDAgEGMB0GA1UdDgQWBBRck1ggWiRzVhAbZFAQ7OmnygdB\n"
"ETAMBggqgRzPVQGDdQUAA0gAMEUCIBVscoZJhUy4eToK4C//LjvhjKK2qpBFac/h\n"
"Pr6yYTLzAiEAiyqrqsGUU5vGkDo5bEpmF1EbnY8xovsM9vCx98yBrVM=\n"
"-----END CERTIFICATE-----\n";

char *rootcacert_pem =
"-----BEGIN CERTIFICATE-----\n"
"MIICAzCCAaegAwIBAgIEFy9CWTAMBggqgRzPVQGDdQUAMFgxCzAJBgNVBAYTAkNO\n"
"MTAwLgYDVQQKDCdDaGluYSBGaW5hbmNpYWwgQ2VydGlmaWNhdGlvbiBBdXRob3Jp\n"
"dHkxFzAVBgNVBAMMDkNGQ0EgQ1MgU00yIENBMB4XDTEyMDgzMTAyMDY1OVoXDTQy\n"
"MDgyNDAyMDY1OVowWDELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFu\n"
"Y2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEXMBUGA1UEAwwOQ0ZDQSBDUyBT\n"
"TTIgQ0EwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATuRh26wmtyKNMz+Pmneo3a\n"
"Sme+BCjRon8SvAxZBgLSuIxNUewq4kNujeb1I4A0yg7xNcjuOgXglAoQv+Tc+P0V\n"
"o10wWzAfBgNVHSMEGDAWgBTkjt3Uo+e2D+4dJ5bNddwlJXJp3TAMBgNVHRMEBTAD\n"
"AQH/MAsGA1UdDwQEAwIBBjAdBgNVHQ4EFgQU5I7d1KPntg/uHSeWzXXcJSVyad0w\n"
"DAYIKoEcz1UBg3UFAANIADBFAiBhP/rmIvles3RK1FfcmmEeS9RZdu+5lCzxF0nk\n"
"cof2QAIhAPVRpqOuceEQHsR77FBe/DgVPqF6lOyoZs0TzTDHrN8c\n"
"-----END CERTIFICATE-----\n";

static int prepare_pem_file(void)
{
	FILE *fp;

	if (!(fp = fopen("double_certs_chain.pem", "wb"))) {
		fprintf(stderr, "fopen() error\n");
		return -1;
	}
	if (fwrite(signcert_pem, 1, strlen(signcert_pem), fp) != strlen(signcert_pem)
		|| fwrite(enccert_pem, 1, strlen(enccert_pem), fp) != strlen(enccert_pem)
		|| fwrite(cacert_pem, 1, strlen(cacert_pem), fp) != strlen(cacert_pem)) {
		fprintf(stderr, "fwrite() error\n");
		return -1;
	}
	fclose(fp);

	if (!(fp = fopen("rootcacert.pem", "wb"))) {
		fprintf(stderr, "fopen() error\n");
		return -1;
	}
	if (fwrite(rootcacert_pem, 1, strlen(rootcacert_pem), fp) != strlen(rootcacert_pem)) {
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
	uint8_t certs[4096];
	size_t certslen;
	uint8_t rootcacert[1024];
	size_t rootcacertlen;

	(void)prepare_pem_file();


	if (!(fp = fopen("double_certs_chain.pem", "rb"))) {
		fprintf(stderr, "fopen() error\n");
		goto err;
	}
	if (x509_certs_from_pem(certs, &certslen, sizeof(certs), fp) != 1) {
		fprintf(stderr, "x509_certs_from_pem() error\n");
		goto err;
	}
	fclose(fp);

	if (!(fp = fopen("rootcacert.pem", "rb"))) {
		fprintf(stderr, "fopen() error\n");
		goto err;
	}
	if (x509_cert_from_pem(rootcacert, &rootcacertlen, sizeof(rootcacert), fp) != 1) {
		fprintf(stderr, "x509_cert_from_pem() error\n");
		goto err;
	}

	int cert_type = X509_cert_chain_client;
	int verify_result = 0;
	if (x509_certs_verify_tlcp(certs, certslen, cert_type, rootcacert, rootcacertlen, 6, &verify_result) != 1) {
		fprintf(stderr, "x509_certs_verify_tlcp() error\n");
		goto err;
	}

	ret = 0;
err:
	if (fp) fclose(fp);
	return ret;
}
