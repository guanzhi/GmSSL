#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/conf.h>

int main()
{
	BIO *bio_err;
	void *ptr;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	ptr = OPENSSL_malloc(1024);

	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);

	return (0);
}
