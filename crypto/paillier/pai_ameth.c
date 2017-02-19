


static int paillier_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
	return 0;
}

static int paillier_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
	return 0;
}

static int paillier_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
	return 0;
}

static int paillier_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
	return 0;
}

static int paillier_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
	return 0;
}

static int paillier_size(const EVP_PKEY *pkey)
{
	return 0;
}

static int paillier_bits(const EVP_PKEY *pkey)
{
	return 0;
}

static int paillier_security_bits(const EVP_PKEY *pkey)
{
	return 0;
}

static void paillier_free(EVP_PKEY *pkey)
{
}

static int paillier_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
	return 1;
}

static int paillier_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)
{
	return 1;
}

static int paillier_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)
{
	return 1;
}

static int paillier_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
	return 1;
}

const EVP_PKEY_ASN1_METHOD paillier_ameth = {
	NID_paillier,
	NID_paillier,
	0,
	"PAILLER",
	"GmSSL Paillier algorithm",

	paillier_pub_decode,
	paillier_pub_encode,
	paillier_pub_cmp,
	paillier_pub_print,

	paillier_priv_decode,
	paillier_priv_encode,
	paillier_priv_print,

	paillier_size,
	paillier_bits,
	paillier_security_bits,

	0, 0, 0, 0,
	paillier_cmp_parameters,
	0, 0,

	paillier_free,
	paillier_ctrl,
	NULL,
	NULL
};
