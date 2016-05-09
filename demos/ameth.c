#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>

int main(int argc, char **argv)
{

	int i;
	
/*
int EVP_PKEY_asn1_get_count(void);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_get0(int idx);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find(ENGINE **pe, int type);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find_str(ENGINE **pe,
                                                   const char *str, int len);

*/

	int count = EVP_PKEY_asn1_get_count();
	printf("EVP_PKEY_asn1_get_count() = %d\n", count);

	for (i = 0; i < count; i++) {
		const EVP_PKEY_ASN1_METHOD *ameth;
		ameth = EVP_PKEY_asn1_get0(i);
		
		int j;
		const unsigned char *p = (const unsigned char *)ameth;
		for (j = 0; j < 64; j++) {
			printf("%02x", p[j]);
		}
		printf("\n");
	}
	
}
