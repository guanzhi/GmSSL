/* ====================================================================
 * Copyright (c) 2014 - 2016 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */
/*
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../e_os.h"

#ifdef OPENSSL_NO_OTP
int main(int argc, char **argv)
{
	printf("NO OTP support\n");
	return 0;
}
#else
# include <openssl/evp.h>
# include <openssl/otp.h>

int main(int argc, char **argv)
{
	/*
	int Tc = 1;
	char *K_str[10] = {
		"1234567890abcdcf1234567890abcdef",
		"1234567890abcdefabcdef1234567890",
		"1234567890abcdef0987654321abcdef",
		"1234567890abcdefabcdcf0987654321",
		"87524138025adcfe2584376195abfedc",
		"87524138025adcfeabfcdc2584376195",
		"adcfc87524138025abfcdc2584376195",
		"58adc3698fe280cb6925010dd236caef",
		"58ade365201d80cbdd236cacf6925010",
		"65201d80cb58ade3dd236caef6925010",
	};
	unsigned char key[10][16] = {{0}};
	int T[10] = {
		1313998979,
		1313998995,
		1313999014,
		1313999047,
		1313999067,
		1313999098,
		1313999131,
		1313999155,
		1313999174,
		1313999189,
	};
	int C[10] = {
		1234,
		5621,
		5621,
		2053,
		2058,
		2056,
		2358,
		2547,
		6031,
		6580,
	};
	int Q[10] = {
		5678,
		3698,
		3698,
		6984,
		3024,
		2018,
		1036,
		2058,
		2058,
		1047,
	};
	int P[10] = {
		814095,
		959691,
		063014,
		302593,
		657337,
		345821,
		629660,
		479821,
		893826,
		607614,
	};
	*/

	return 0;
}
#endif
