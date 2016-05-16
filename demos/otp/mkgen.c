#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <openssl/rand.h>

int main(int argc, char **argv)
{
	unsigned char mk[32];
	int i;

	RAND_bytes(mk, sizeof(mk));
	
	for (i = 0; i < sizeof(mk); i++) {
		printf("%02x", mk[i]);
	}
	printf("\n");
	
	return 0;
}

