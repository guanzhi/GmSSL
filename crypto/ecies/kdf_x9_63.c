#include <string.h>
#include "kdf.h"


#ifdef CPU_BIGENDIAN
#define cpu_to_be16(v) (v)
#define cpu_to_be32(v) (v)
#else
#define cpu_to_be16(v) ((v << 8) | (v >> 8))
#define cpu_to_be32(v) ((cpu_to_be16(v) << 16) | cpu_to_be16(v >> 16))
#endif

static void *x963_kdf(const EVP_MD *md, const void *share, size_t sharelen,
	void *key, size_t keylen)
{
	EVP_MD_CTX ctx;
	unsigned int counter = 1; //FIXME: uint32_t
	unsigned int counter_be;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	int rlen = (int)keylen;
	unsigned char *out = key;

	EVP_MD_CTX_init(&ctx);

	while (rlen > 0) {
		counter_be = cpu_to_be32(counter);
		counter++;

		EVP_DigestInit(&ctx, md);
		EVP_DigestUpdate(&ctx, share, sharelen);
		EVP_DigestUpdate(&ctx, (const void *)&counter_be, 4);
		EVP_DigestFinal(&ctx, dgst, &dgstlen);

		memcpy(out, dgst, (int)dgstlen > rlen ? rlen : dgstlen);
		rlen -= dgstlen;
		out += dgstlen;
	}

	EVP_MD_CTX_cleanup(&ctx);
	return key;
}

static void *x963_md5kdf(const void *share, size_t sharelen,
	void *key, size_t *keylen)
{
	return x963_kdf(EVP_md5(), share, sharelen, key, *keylen);
}

static void *x963_rmd160kdf(const void *share, size_t sharelen,
	void *key, size_t *keylen)
{
	return x963_kdf(EVP_ripemd160(), share, sharelen, key, *keylen);
}

static void *x963_sha1kdf(const void *share, size_t sharelen,
	void *key, size_t *keylen)
{
	return x963_kdf(EVP_sha1(), share, sharelen, key, *keylen);
}

static void *x963_sha224kdf(const void *share, size_t sharelen,
	void *key, size_t *keylen)
{
	return x963_kdf(EVP_sha224(), share, sharelen, key, *keylen);
}

static void *x963_sha256kdf(const void *share, size_t sharelen,
	void *key, size_t *keylen)
{
	return x963_kdf(EVP_sha256(), share, sharelen, key, *keylen);
}

static void *x963_sha384kdf(const void *share, size_t sharelen,
	void *key, size_t *keylen)
{
	return x963_kdf(EVP_sha384(), share, sharelen, key, *keylen);
}

static void *x963_sha512kdf(const void *share, size_t sharelen,
	void *key, size_t *keylen)
{
	return x963_kdf(EVP_sha512(), share, sharelen, key, *keylen);
}

static void *x963_sm3kdf(const void *share, size_t sharelen,
	void *key, size_t *keylen)
{
	return x963_kdf(EVP_sm3(), share, sharelen, key, *keylen);
}

KDF_FUNC KDF_get_x9_63(const EVP_MD *md)
{
	if 	(md == EVP_md5())
		return x963_md5kdf;
	else if (md == EVP_ripemd160())
		return x963_rmd160kdf;
	else if (md == EVP_sha1())
		return x963_sha1kdf;
	else if (md == EVP_sha224())	
		return x963_sha224kdf;
	else if (md == EVP_sha256())
		return x963_sha256kdf;
	else if (md == EVP_sha384())
		return x963_sha384kdf;
	else if (md == EVP_sha512())
		return x963_sha512kdf;
	else if (md == EVP_sm3())
		return x963_sm3kdf;

	return NULL;
}

