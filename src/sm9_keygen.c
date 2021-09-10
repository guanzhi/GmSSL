/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */



int sm9_hash1(bignum_t r, const char *id, size_t idlen, uint8_t hid)
{
	bignum_t h;
	SM3_CTX ctx1;
	SM3_CTX ctx2;

	uint8_t prefix[1] = {0x01};
	uint8_t ct1[4] = {0x00, 0x00, 0x00, 0x01};
	uint8_t ct2[4] = {0x00, 0x00, 0x00, 0x02};
	uint8_t buf[64];

	sm3_init(&ctx1);
	sm3_update(&ctx1, prefix, sizeof(prefix));
	sm3_update(&ctx1, id, idlen);
	sm3_update(&ctx1, &hid, 1);

	memcpy(&ctx2, &ctx1, sizeof(SM3_CTX));

	sm3_update(&ctx1, ct1, sizeof(ct1));
	sm3_update(&ctx2, ct2, sizeof(ct2));
	sm3_finish(&ctx1, buf);
	sm3_finish(&ctx2, buf + 32);

		
}
