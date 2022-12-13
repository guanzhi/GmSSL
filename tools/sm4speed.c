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
#include <gmssl/hex.h>
#include <gmssl/sm4.h>
#include <gmssl/error.h>
#include <gmssl/rand.h>

#ifdef WIN32
#include <wincrypt.h>

static volatile int finish;

VOID CALLBACK TimerProc_sm4(HWND hwnd, UINT message, UINT iTimerID, DWORD dwTime)
{
	finish = 0;
}

int test_sm4()
{
	uint8_t user_key[16] = {
		0x01,
		0x23,
		0x45,
		0x67,
		0x89,
		0xab,
		0xcd,
		0xef,
		0xfe,
		0xdc,
		0xba,
		0x98,
		0x76,
		0x54,
		0x32,
		0x10,
	};
	uint8_t iv[16] = {
		0x01,
		0x23,
		0x45,
		0x67,
		0x89,
		0xab,
		0xcd,
		0xef,
		0xfe,
		0xdc,
		0xba,
		0x98,
		0x76,
		0x54,
		0x32,
		0x10,
	};
	uint8_t ctr[16] = {0};
	uint8_t mac[16] = {0};
	uint8_t aad[16] = {
		0x01,
		0x23,
		0x45,
		0x67,
		0x89,
		0xab,
		0xcd,
		0xef,
		0xfe,
		0xdc,
		0xba,
		0x98,
		0x76,
		0x54,
		0x32,
		0x10,
	};
	uint8_t out[16384] = {0};

	SM4_KEY key;
	int sizebox[] = {16, 64, 256, 1024, 8192, 16384};
	int countbox[18] = {0};
	uint8_t *testhex[];
	HCRYPTPROV hCryptProv;

	testhex = (uint8_t **)malloc(sizeof(uint8_t *) * 6);
	for (int i = 0; i < 6; i++)
	{
		testhex[i] = (uint8_t *)malloc(sizebox[i]);
		CryptGenRandom(hCryptProv, sizebox[i], testhex[i]);
	}

	int count;

	sm4_set_encrypt_key(&key, user_key);

	for (int i = 0; i < 6; i++)
	{
		finish = 1;
		count = 0;
		printf("Doing sm4-cbc for 3s on %d size blocks: ", sizebox[i]);
		UINT_PTR iTimerID = SetTimer(NULL, 0, 3000, TimerProc_sm4);
		while (finish)
		{
			sm4_cbc_encrypt(&key, iv, testhex[i], sizebox[i] / 16, out);
			count++;
		}
		KillTimer(NULL, iTimerID);
		countbox[i] = count;
		printf("%d sm4-cbc's in 3s\n", count);
	}
	for (int i = 0; i < 6; i++)
	{
		finish = 1;
		count = 0;
		printf("Doing sm4-ctr for 3s on %d size blocks: ", sizebox[i]);
		UINT_PTR iTimerID = SetTimer(NULL, 0, 3000, TimerProc);
		while (finish)
		{
			sm4_ctr_encrypt(&key, ctr, testhex[i], sizebox[i], out);
			count++;
		}
		KillTimer(NULL, iTimerID);
		countbox[i + 6] = count;
		printf("%d sm4-ctr's in 3s\n", count);
	}
	for (int i = 0; i < 6; i++)
	{
		finish = 1;
		count = 0;
		printf("Doing sm4-gcm for 3s on %d size blocks: ", sizebox[i]);
		UINT_PTR iTimerID = SetTimer(NULL, 0, 3000, TimerProc);
		while (finish)
		{
			sm4_gcm_encrypt(&key, iv, 16, aad, 16, testhex[i], sizebox[i], out, 16, mac);
			count++;
		}
		KillTimer(NULL, iTimerID);
		countbox[i + 12] = count;
		printf("%d sm4-gcm's in 3s\n", count);
	}
	printf("type\t\t16 bytes\t64 bytes\t256 bytes\t1024 bytes\t8192 bytes\t16384 bytes\n");
	printf("sm4-cbc\t");
	for (int i = 0; i < 6; i++)
	{
		printf("\t%.2fK", countbox[i] * sizebox[i] / 1024 / 3.00);
	}
	printf("\n");
	printf("sm4-ctr\t");
	for (int i = 0; i < 6; i++)
	{
		printf("\t%.2fK", countbox[i + 6] * sizebox[i] / 1024 / 3.00);
	}
	printf("\n");
	printf("sm4-gcm\t");
	for (int i = 0; i < 6; i++)
	{
		printf("\t%.2fK", countbox[i + 12] * sizebox[i] / 1024 / 3.00);
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

void sig_alm_handler_sm4(int sig_num)
{
	if (sig_num = SIGALRM)
		finish = 0;
}

int test_sm4()
{
	uint8_t user_key[16] = {
		0x01,
		0x23,
		0x45,
		0x67,
		0x89,
		0xab,
		0xcd,
		0xef,
		0xfe,
		0xdc,
		0xba,
		0x98,
		0x76,
		0x54,
		0x32,
		0x10,
	};
	uint8_t iv[16] = {
		0x01,
		0x23,
		0x45,
		0x67,
		0x89,
		0xab,
		0xcd,
		0xef,
		0xfe,
		0xdc,
		0xba,
		0x98,
		0x76,
		0x54,
		0x32,
		0x10,
	};
	uint8_t ctr[16] = {0};
	uint8_t mac[16] = {0};
	uint8_t aad[16] = {
		0x01,
		0x23,
		0x45,
		0x67,
		0x89,
		0xab,
		0xcd,
		0xef,
		0xfe,
		0xdc,
		0xba,
		0x98,
		0x76,
		0x54,
		0x32,
		0x10,
	};
	uint8_t out[16384] = {0};
	int count;

	SM4_KEY key;
	int sizebox[] = {16, 64, 256, 1024, 8192, 16384};
	int countbox[18] = {0};
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

	signal(SIGALRM, sig_alm_handler_sm4);

	struct itimerval new_value, old_value;
	new_value.it_value.tv_sec = 3;
	new_value.it_value.tv_usec = 0;
	new_value.it_interval.tv_sec = 0;
	new_value.it_interval.tv_usec = 0;

	sm4_set_encrypt_key(&key, user_key);

	for (int i = 0; i < 6; i++)
	{
		finish = 1;
		count = 0;
		printf("Doing sm4-cbc for 3s on %d size blocks: ", sizebox[i]);
		setitimer(ITIMER_REAL, &new_value, &old_value);
		while (finish)
		{
			sm4_cbc_encrypt(&key, iv, testhex[i], sizebox[i] / 16, out);
			count++;
		}

		countbox[i] = count;
		printf("%d sm4-cbc's in 3s\n", count);
	}
	for (int i = 0; i < 6; i++)
	{
		finish = 1;
		count = 0;
		printf("Doing sm4-ctr for 3s on %d size blocks: ", sizebox[i]);
		setitimer(ITIMER_REAL, &new_value, &old_value);
		while (finish)
		{
			sm4_ctr_encrypt(&key, ctr, testhex[i], sizebox[i], out);
			count++;
		}

		countbox[i + 6] = count;
		printf("%d sm4-ctr's in 3s\n", count);
	}
	for (int i = 0; i < 6; i++)
	{
		finish = 1;
		count = 0;
		printf("Doing sm4-gcm for 3s on %d size blocks: ", sizebox[i]);
		setitimer(ITIMER_REAL, &new_value, &old_value);
		while (finish)
		{
			sm4_gcm_encrypt(&key, iv, 16, aad, 16, testhex[i], sizebox[i], out, 16, mac);
			count++;
		}
		countbox[i + 12] = count;
		printf("%d sm4-gcm's in 3s\n", count);
	}
	printf("type\t\t16 bytes\t64 bytes\t256 bytes\t1024 bytes\t8192 bytes\t16384 bytes\n");
	printf("sm4-cbc\t");
	for (int i = 0; i < 6; i++)
	{
		printf("\t%.2fK", countbox[i] * sizebox[i] / 1024 / 3.00);
	}
	printf("\n");
	printf("sm4-ctr\t");
	for (int i = 0; i < 6; i++)
	{
		printf("\t%.2fK", countbox[i + 6] * sizebox[i] / 1024 / 3.00);
	}
	printf("\n");
	printf("sm4-gcm\t");
	for (int i = 0; i < 6; i++)
	{
		printf("\t%.2fK", countbox[i + 12] * sizebox[i] / 1024 / 3.00);
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

int sm4speed_main(void)
{
	test_sm4();
	return 1;
}
