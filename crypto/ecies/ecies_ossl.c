



int ossl_ecies_encrypt(int type, const unsigned char *in, size_t inlen,
                       unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	return 0;
}

ECIES_CIPHERTEXT_VALUE *ossl_ecies_do_encrypt(int type, const unsigned char *in,
                                              size_t inlen, EC_KEY *ec_key)
{
	return NULL;
}

int ossl_ecies_decrypt(int type, const unsigned char *in, size_t inlen,
                       unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	return 0;
}

int ossl_ecies_do_decrypt(int type, const ECIES_CIPHERTEXT_VALUE *in,
                      unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	return NULL;
}

