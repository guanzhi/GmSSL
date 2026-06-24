/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>


static int test_sm2_key_exchange(void)
{
	SM2_KEY a;
	SM2_KEY b;
	SM2_KEY ra;
	SM2_KEY rb;
	uint8_t ra_octets[65];
	uint8_t rb_octets[65];
	uint8_t ua[65];
	uint8_t vb[65];
	uint8_t ska[48];
	uint8_t skb[48];
	uint8_t sa[32];
	uint8_t sb[32];
	const char ida[] = "Alice";
	const char idb[] = "Bob";

	if (sm2_key_generate(&a) != 1
		|| sm2_key_generate(&b) != 1
		|| sm2_key_generate(&ra) != 1
		|| sm2_key_generate(&rb) != 1
		|| sm2_z256_point_to_uncompressed_octets(&ra.public_key, ra_octets) != 1
		|| sm2_z256_point_to_uncompressed_octets(&rb.public_key, rb_octets) != 1) {
		error_print();
		return -1;
	}

	if (sm2_key_exchange(1, &a, ida, sizeof(ida) - 1, &b, idb, sizeof(idb) - 1,
			&ra, rb_octets, ua, sizeof(ska), ska) != 1
		|| sm2_key_exchange(0, &b, idb, sizeof(idb) - 1, &a, ida, sizeof(ida) - 1,
			&rb, ra_octets, vb, sizeof(skb), skb) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(ska, skb, sizeof(ska)) != 0 || memcmp(ua, vb, sizeof(ua)) != 0) {
		error_print();
		return -1;
	}

	if (sm2_key_exchange_compute_confirm(1, &a, ida, sizeof(ida) - 1, &b, idb, sizeof(idb) - 1,
			&ra, rb_octets, ua, sa) != 1
		|| sm2_key_exchange_compute_confirm(0, &b, idb, sizeof(idb) - 1, &a, ida, sizeof(ida) - 1,
			&rb, ra_octets, vb, sb) != 1) {
		error_print();
		return -1;
	}
	if (sm2_key_exchange_verify_confirm(1, &a, ida, sizeof(ida) - 1, &b, idb, sizeof(idb) - 1,
			&ra, rb_octets, ua, sb) != 1
		|| sm2_key_exchange_verify_confirm(0, &b, idb, sizeof(idb) - 1, &a, ida, sizeof(ida) - 1,
			&rb, ra_octets, vb, sa) != 1) {
		error_print();
		return -1;
	}

	sb[0] ^= 0x01;
	if (sm2_key_exchange_verify_confirm(1, &a, ida, sizeof(ida) - 1, &b, idb, sizeof(idb) - 1,
			&ra, rb_octets, ua, sb) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm2_key_exchange() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
