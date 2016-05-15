#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

char *cert_file = "server.pem";

int main(int argc, char **argv)
{

	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;

	SSL_library_init();
	SSL_load_error_strings();



	if (!(ctx = SSL_CTX_new(GMSSLv1_method()))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!SSL_CTX_use_certificate_chain_file(ctx, cert_file)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!SSL_CTX_use_PrivateKey_file(ctx, cert_file, SSL_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(ssl = SSL_new(ctx))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	

end:
	return 0;
}

