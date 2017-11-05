

#ifdef OPENSSL_NO_MACRO
# ifndef OPENSSL_NO_RSA
int EVP_PKEY_assign_RSA(EVP_PKEY *pkey, RSA *rsa)
{
	return EVP_PKEY_assign(pkey, EVP_PKEY_RSA, (char *)rsa);
}
# endif

# ifndef OPENSSL_NO_DSA
int EVP_PKEY_assign_DSA(EVP_PKEY *pkey, DSA *dsa)
{
	return EVP_PKEY_assign(pkey, EVP_PKEY_DSA, (char *)dsa);
}
# endif

# ifndef OPENSSL_NO_DH
int EVP_PKEY_assign_DH(EVP_PKEY *pkey, DH *dh)
{
	return EVP_PKEY_assign(pkey, EVP_PKEY_DH, (char *)dh);
}
# endif

# ifndef OPENSSL_NO_EC
int EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, EC_KEY *ec_key)
{
	return EVP_PKEY_assign(pkey, EVP_PKEY_EC, (char *)ec_key);
}
# endif

# ifndef OPENSSL_NO_PAILLIER
int EVP_PKEY_assign_PAILLIER(EVP_PKEY *pkey, PAILLIER *paillier)
{
	return EVP_PKEY_assign(pkey, EVP_PKEY_PAILLIER, (char *)paillier);
}
#endif

const EVP_MD *EVP_get_digestbynid(int nid)
{
	return EVP_get_digestbyname(OBJ_nid2sn(nid));
}

const EVP_MD *EVP_get_digestbyobj(ASN1_OBJECT *obj)
{
	return EVP_get_digestbynid(OBJ_obj2nid(obj));
}

const EVP_CIPHER *EVP_get_cipherbynid(int nid)
{
	return EVP_get_cipherbyname(OBJ_nid2sn(nid));
}

const EVP_CIPHER *EVP_get_cipherbyobj(ASN1_OBJECT *obj)
{
	return EVP_get_cipherbynid(OBJ_obj2nid(obj));
}

int EVP_MD_nid(const EVP_MD *md)
{
	return EVP_MD_type(md);
}

const char *EVP_MD_name(const EVP_MD *md)
{
	return OBJ_nid2sn(EVP_MD_nid(md));
}

int EVP_MD_CTX_size(EVP_MD_CTX *ctx)
{
	return EVP_MD_size(EVP_MD_CTX_md(ctx));
}

int EVP_MD_CTX_block_size(EVP_MD_CTX *ctx)
{
	return EVP_MD_block_size(EVP_MD_CTX_md(ctx));
}

int EVP_MD_CTX_type(EVP_MD_CTX *ctx)
{
	return EVP_MD_type(EVP_MD_CTX_md(ctx));
}

const char *EVP_CIPHER_name(const EVP_CIPHER *cipher)
{
	return OBJ_nid2sn(EVP_CIPHER_nid(cipher));
}

int EVP_CIPHER_mode(const EVP_CIPHER *cipher)
{
	return (EVP_CIPHER_flags(cipher) & EVP_CIPH_MODE);
}

int EVP_CIPHER_CTX_type(EVP_CIPHER_CTX *ctx)
{
	return EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(ctx));
}

# if OPENSSL_API_COMPAT < 0x10100000L
int EVP_CIPHER_CTX_flags(EVP_CIPHER_CTX *ctx)
{
	return EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(ctx));
}
# endif

int EVP_CIPHER_CTX_mode(EVP_CIPHER_CTX *ctx)
{
	return EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(ctx));
}

long EVP_ENCODE_LENGTH(long l)
{
	return (((l+2)/3*4)+(l/48+1)*2+80);
}

long EVP_DECODE_LENGTH(long l)
{
	return ((l+3)/4*3+80);
}

__owur int EVP_SignInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
                           ENGINE *impl)
{
	return EVP_DigestInit_ex(ctx, type, impl);
}

__owur int EVP_SignInit(EVP_MD_CTX *ctx, const EVP_MD *type)
{
	return EVP_DigestInit(ctx, type);
}

__owur int EVP_SignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
	return EVP_DigestUpdate(ctx, d, cnt);
}

__owur int EVP_VerifyInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
                           ENGINE *impl)
{
	return EVP_DigestInit_ex(ctx, type, impl);
}

__owur int EVP_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *type)
{
	return EVP_DigestInit(ctx, type);
}

__owur int EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
	return EVP_DigestUpdate(ctx, d, cnt);
}

/*__owur*/ int EVP_OpenUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              int *outl, const unsigned char *in, int inl)
{
	return EVP_DecryptUpdate(ctx, out, outl, in, inl);
}

/*__owur*/ int EVP_SealUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              int *outl, const unsigned char *in, int inl)
{
	return EVP_EncryptUpdate(ctx, out, outl, in, inl);
}

__owur int EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
	return EVP_DigestUpdate(ctx, d, cnt);
}

__owur int EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
	return EVP_DigestUpdate(ctx, d, cnt);
}

long BIO_get_md(BIO *bio, const EVP_MD **pmd)
{
	return BIO_ctrl(bio,BIO_C_GET_MD,0,(char *)pmd);
}

long BIO_get_md_ctx(BIO *bio, EVP_MD_CTX **pmctx)
{
	return BIO_ctrl(bio,BIO_C_GET_MD_CTX,0,(char *)pmctx);
}

long BIO_set_md_ctx(BIO *bio, EVP_MD_CTX *mctx)
{
	return BIO_ctrl(bio,BIO_C_SET_MD_CTX,0,(char *)mctx);
}

long BIO_get_cipher_status(BIO *bio)
{
	return BIO_ctrl(bio,BIO_C_GET_CIPHER_STATUS,0,NULL);
}

long BIO_get_cipher_ctx(BIO *bio, EVP_CIPHER_CTX *pcctx)
{
	return BIO_ctrl(bio,BIO_C_GET_CIPHER_CTX,0,(char *)pcctx)
}

int EVP_add_cipher_alias(int type, const char *alias)
{
	return OBJ_NAME_add(alias,
		OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS, type);
}

int EVP_add_digest_alias(int type, const char *alias)
{
	return OBJ_NAME_add(alias,
		OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS, type);
}

int EVP_delete_cipher_alias(const char *alias)
{
	return OBJ_NAME_remove(alias,
		OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);
}

int EVP_delete_digest_alias(const char *alias)
{
	return OBJ_NAME_remove(alias,
		OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);
}

EVP_MD_CTX *EVP_MD_CTX_create(void)
{
	return EVP_MD_CTX_new();
}
int EVP_MD_CTX_init(EVP_MD_CTX *ctx)
{
	return EVP_MD_CTX_reset(ctx);
}

void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx)
{
	EVP_MD_CTX_free(ctx);
}

# if OPENSSL_API_COMPAT < 0x10100000L
int EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *ctx)
{
	return EVP_CIPHER_CTX_reset(ctx);
}

int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *ctx)
{
	return EVP_CIPHER_CTX_reset(ctx);
}
# endif

int OPENSSL_add_all_algorithms_conf(void)
{
	return OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                        | OPENSSL_INIT_ADD_ALL_DIGESTS
                        | OPENSSL_INIT_LOAD_CONFIG, NULL);
}

int OPENSSL_add_all_algorithms_noconf(void)
{
	return OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                        | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
}

int OpenSSL_add_all_algorithms(void)
{
# ifdef OPENSSL_LOAD_CONF
	return OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                        | OPENSSL_INIT_ADD_ALL_DIGESTS
                        | OPENSSL_INIT_LOAD_CONFIG, NULL);
# else
	return OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                        | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
# endif
}

int OpenSSL_add_all_ciphers(void)
{
	return OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL);
}

int OPENSSL_add_all_digests(void)
{
	return OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
}

void OPENSSL_cleanup(void)
{
}

int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
	return EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG,
                                        EVP_PKEY_CTRL_MD, 0, (void *)md);
}

int EVP_PKEY_CTX_get_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
	return EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG,
                                        EVP_PKEY_CTRL_GET_MD, 0, (void *)pmd);
}

int EVP_PKEY_CTX_set_mac_key(EVP_PKEY_CTX *ctx, const unsigned char *key, int keylen)
{
	return EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
                                  EVP_PKEY_CTRL_SET_MAC_KEY, len, (void *)key);
}
#endif
