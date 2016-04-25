#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/assert.h>

int main(int argc, char **argv)
{
	const char *engine_id = "SKF";
	ENGINE *engine = NULL;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX ctx;
	unsigned char key[16];
	unsigned char iv[16];
	const char *msg1 = "hello world";
	const char *msg2 = "12345678";
	unsigned char buf[128];
	int len;

	ENGINE_load_builtin_engines();
	engine = ENGINE_by_id(engine_id);

	OPENSSL_assert(engine != NULL);

	rv = ENGINE_init(engine);
	OPENSSL_assert(rv == 1);

	cipher = ENGINE_get_cipher(engine, NID_sm1_cbc);

	EVP_CIPHER_CTX_init(&ctx);

	rv = RAND_bytes(key, (int)sizeof(key));
	rv = RAND_bytes(iv, (int)sizeof(iv));

	rv = EVP_EncryptInit_ex(&ctx, cipher, engine, key, iv);

	p = buf;
	rv = EVP_EncryptUpdate(&ctx, p, &len, (unsigned char *)msg1, (int)strlen(msg1));
	
	p += len;
	rv = EVP_EncryptUpdate(&ctx, p, &len, (unsigned char *)msg2, (int)strlen(msg2));
	
	p += len;
	rv = EVP_EncryptFinal_ex(&ctx, p, &len);

	p += len;


	EVP_CIPHER_CTX_cleanup(&ctx);
	ENGINE_finish(engine);
	ENGINE_free(engine);

	return 0;	
}

