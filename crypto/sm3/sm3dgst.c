#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include "sm3.h"

/*
 * usage of sm3dgst:
 * ./sm3dgst <file>
 * 324234234234235234234234234234
 *
 * echo "hello world" | sm3dgst
 * lksjdlfksdjlfkjsdlfkjsdlfkjsdljkfffffffldjfk=
 *
 */

int main(int argc, char **argv)
{
	sm3_ctx_t ctx;
	unsigned char dgst[SM3_DIGEST_LENGTH];
	unsigned char buf[4096];
	ssize_t len;
	int i;

	if (argc > 1) {
		printf("usage: %s < file\n", basename(argv[0]));
		return 0;
	}

	sm3_init(&ctx);
	
	while ((len = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
		sm3_update(&ctx, buf, len);
	}
	memset(dgst, 0, sizeof(dgst));
	sm3_final(&ctx, dgst);

	for (i = 0; i < sizeof(dgst); i++) {
		printf("%02x", dgst[i]);
	}
	printf("\n");

	return 0;	 
}

