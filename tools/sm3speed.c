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
#include <stdint.h>
#include <gmssl/sm3.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>

#ifdef WIN32
#include <wincrypt.h>

static volatile int finish;

VOID CALLBACK TimerProc_sm3(HWND hwnd, UINT message, UINT iTimerID, DWORD dwTime)
{
	finish = 0;
}

int test_sm3()
{
	int sizebox[] = {16, 64, 256, 1024, 8192, 16384};
	int countbox[6] = {0};
	uint8_t **testhex;
	HCRYPTPROV hCryptProv;

	testhex = (uint8_t **)malloc(sizeof(uint8_t *) * 6);
	for (int i = 0; i < 6; i++)
	{
		testhex[i] = (uint8_t *)malloc(sizebox[i]);
		CryptGenRandom(hCryptProv, sizebox[i], testhex[i]);
	}

	uint8_t dgst[32];
	int count;

	for (int i = 0; i < 6; i++)
	{
		finish = 1;
		count = 0;
		printf("Doing sm3 for 3s on %d size blocks: ", sizebox[i]);
		UINT_PTR iTimerID = SetTimer(NULL, 0, 3000, TimerProc_sm3);
		while (finish)
		{
			sm3_digest(testhex[i], sizebox[i], dgst);
			count++;
		}
		KillTimer(NULL, iTimerID);
		countbox[i] = count;
		printf("%d sm3's in 3s\n", count);
	}
	printf("type\t\t16 bytes\t64 bytes\t256 bytes\t1024 bytes\t8192 bytes\t16384 bytes\n");
	printf("sm3\t");
	for (int i = 0; i < 6; i++)
	{
		printf("\t%.2fK", countbox[i] * sizebox[i] / 1024 / 3.00);
	}
	printf("\n");

	for (int i = 0; i < 6; i++)
	{
		free(testhex[i]);
	}
	free(testhex);
	return 1;
}
#else
#include <signal.h>
#include <sys/time.h>

static volatile int finish;

void sig_alm_handler_sm3(int sig_num)
{
	if (sig_num = SIGALRM)
		finish = 0;
}

int test_sm3()
{
	int sizebox[] = {16, 64, 256, 1024, 8192, 16384};
	int countbox[6] = {0};
	uint8_t **testhex;

	FILE *fs_p = fopen("/dev/urandom", "r");
	if (NULL == fs_p)
	{
		printf("Can not open /dev/urandom\n");
		return -1;
	}

	testhex = (uint8_t **)malloc(sizeof(uint8_t *) * 6);
	for (int i = 0; i < 6; i++)
	{
		testhex[i] = (uint8_t *)malloc(sizebox[i]);
		fread(testhex[i], sizebox[i], 1, fs_p);
	}

	fclose(fs_p);

	uint8_t dgst[32];
	int count;

	signal(SIGALRM, sig_alm_handler_sm3);

	struct itimerval new_value, old_value;
	new_value.it_value.tv_sec = 3;
	new_value.it_value.tv_usec = 0;
	new_value.it_interval.tv_sec = 0;
	new_value.it_interval.tv_usec = 0;

	for (int i = 0; i < 6; i++)
	{
		finish = 1;
		count = 0;
		printf("Doing sm3 for 3s on %d size blocks: ", sizebox[i]);
		setitimer(ITIMER_REAL, &new_value, &old_value);
		while (finish)
		{
			sm3_digest(testhex[i], sizebox[i], dgst);
			count++;
		}
		countbox[i] = count;
		printf("%d sm3's in 3s\n", count);
	}
	printf("type\t\t16 bytes\t64 bytes\t256 bytes\t1024 bytes\t8192 bytes\t16384 bytes\n");
	printf("sm3\t");
	for (int i = 0; i < 6; i++)
	{
		printf("\t%.2fK", countbox[i] * sizebox[i] / 1024 / 3.00);
	}
	printf("\n");

	for (int i = 0; i < 6; i++)
	{
		free(testhex[i]);
	}
	free(testhex);
	return 1;
}
#endif

int sm3speed_main(void)
{
	test_sm3();
	return 1;
}
