/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>


static const char *usage = "-in private.pem -pass pass / -pubin public.pem";

static const char *options =
"Options\n"
"    -pass pass                  Password to encrypt the private key\n"
"    -in pem                     Input private key in PEM format\n"
"    -pubin pem                  Input public key in PEM format\n"
"\n";


int sm2keyparse_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *pass = NULL;
	char *pubinfile = NULL;
    char *infile = NULL;
	FILE *pubinfp = NULL;
    FILE *infp = NULL;
	SM2_KEY key;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, usage);
			printf("%s\n", options);
			ret = 0;
			goto end;
		} else if(!strcmp(*argv,"-pubin")){
            if (--argc<1) goto bad;
            pubinfile=(*++argv);
            if (!(pubinfp = fopen(pubinfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, pubinfile, strerror(errno));
				goto end;
			}
            goto pubkey;
        } else if(!strcmp(*argv, "-in")){
            if (--argc<1) goto bad;
            infile = *(++argv);
            if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
        } else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "%s: `%s` option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!pass) {
		fprintf(stderr, "%s: `-pass` option required\n", prog);
		goto end;
	}

	if (sm2_private_key_info_decrypt_from_pem(&key, pass, infp) != 1) {
		fprintf(stderr, "%s: private key decryption failure\n", prog);
		goto end;
	} else {
        printf("\n");
        for(int i=0;i<4;i++){
            for(int j=0;j<8;j++){
                printf("%02x ",key.private_key[i*8+j]);
            }
            printf("\n");
        }
        printf("\n");
    }

    if(pubinfile){
pubkey:
        if (sm2_public_key_info_from_pem(&key, pubinfp) != 1) {
                fprintf(stderr, "%s: parse public key failed\n", prog);
                goto end;
        } else {
            printf("\nx:\n");
            for(int i=0;i<4;i++){
                for(int j=0;j<8;j++){
                    printf("%02x ",key.public_key.x[i*8+j]);
                }
                printf("\n");
            }
            printf("\n");

            printf("y:\n");
            for(int i=0;i<4;i++){
                for(int j=0;j<8;j++){
                    printf("%02x ",key.public_key.y[i*8+j]);
                }
                printf("\n");
            }
            printf("\n");
        }
    }

end:
	gmssl_secure_clear(&key, sizeof(key));
	if (infile && infp) fclose(infp);
	if (pubinfile && pubinfp) fclose(pubinfp);
	return ret;
}

