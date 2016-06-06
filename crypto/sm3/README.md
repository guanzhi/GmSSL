## SM3 Sub-library of GMSSL

SM3 Cryptographic Hash Algorithm is a chinese national cryptographic hash
algorithm standard published by the State Cryptography Administration Office
of Security Commercial Code Administration (OSCCA) of China in December 2010.
A draft of this algorithm can be found at

[http://tools.ietf.org/html/draft-shen-sm3-hash-00](http://tools.ietf.org/html/draft-shen-sm3-hash-00 "RFC Draft")


The SM3 take input messages as 512 bits blocks and generates
256 bits digest values, same as SHA-256.

The `SM3` sub-library of GmSSL provides the implementation of SM3 hash
algorithm, with init/update/final style of interfaces. There is also a
demo program in `demo/gmssl/sm3.c` on how to implement a command line
tool with the the inner API of SM3 sub-library.

### Usage

The SM3 sub-library provides the following C API:

```
	void sm3_init(sm3_ctx_t *ctx);
	void sm3_update(sm3_ctx_t *ctx, const unsigned char* data, size_t data_len);
	void sm3_final(sm3_ctx_t *ctx, unsigned char digest[SM3_DIGEST_LENGTH]);
	void sm3_compress(uint32_t digest[8], const unsigned char block[SM3_BLOCK_SIZE]);
	void sm3(const unsigned char *data, size_t datalen, unsigned char digest[SM3_DIGEST_LENGTH]);

	void sm3_hmac_init(sm3_hmac_ctx_t *ctx, const unsigned char *key, size_t key_len);
	void sm3_hmac_update(sm3_hmac_ctx_t *ctx, const unsigned char *data, size_t data_len);
	void sm3_hmac_final(sm3_hmac_ctx_t *ctx, unsigned char mac[sm3_hmac_MAC_SIZE]);
	void sm3_hmac(const unsigned char *data, size_t data_len,
		const unsigned char *key, size_t key_len, unsigned char mac[sm3_hmac_MAC_SIZE]);
```

Example on using C API to digest a message:

```
	unsigend char buffer[SM3_DIGEST_LENGTH];
	sm3("hello", strlen("hello"), buffer);
```

Example on using C API to digest a stream:

```
	unsigned char dgst[SM3_DIGEST_LENGTH];
	sm3_ctx_t ctx;
	sm3_init(&ctx);
	sm3_update(&ctx, "hello", strlen("hello"));
	sm3_update(&ctx, "world", strlen("world"));
	sm3_final(&ctx, dgst);
```

Example on using C API to generate a HMAC tag:

```
	unsigned char mac[sm3_hmac_MAC_SIZE];
	sm3_hmac_ctx_t ctx;
	unsigned char key[16];
	sm3_hmac_init(&ctx, key, sizeof(key));
	sm3_hmac_update(&ctx, "hello", strlen("hello"));
	sm3_hmac_update(&ctx, "world", strlen("world"));
	sm3_hmac_final(&ctx, mac);
```

