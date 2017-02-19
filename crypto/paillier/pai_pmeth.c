





static int pkey_paillier_init(EVP_PKEY_CTX *ctx)
{
	return 0;
}

static int pkey_paillier_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	return 0;
}

static void pkey_paillier_cleanup(EVP_PKEY_CTX *ctx)
{
}

static int pkey_paillier_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
	return 0;
}

static int pkey_paillier_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
	return 0;
}

static int pkey_paillier_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	return 0;
}

static int pkey_paillier_ctrl_str(EVP_PKEY_CTX *ctx,
                            const char *type, const char *value)
{
	return 0;
}

const EVP_PKEY_METHOD paillier_pmeth = {
	EVP_PKEY_PAILLIER,
	0,
	pkey_paillier_init,
	pkey_paillier_copy,
	pkey_paillier_cleanup,

	0, 0,

	0,
	pkey_paillier_keygen,

	0, 0,
	0, 0,
	0, 0,
	0, 0, 0, 0,

	0,
	pkey_paillier_encrypt,
	0,
	pkey_paillier_decrypt,

	0, 0,

	pkey_paillier_ctrl,
	pkey_paillier_ctrl_str
};

