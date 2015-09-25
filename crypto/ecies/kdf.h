#ifndef HEADER_KDF_H
#define HEADER_KDF_H

#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef void *(*KDF_FUNC)(const void *in, size_t inlen, void *out, size_t *outlen);

KDF_FUNC KDF_get_x9_63(const EVP_MD *md);
KDF_FUNC KDF_get_nist_concatenation(void);
KDF_FUNC KDF_get_tls_kdf(void);
KDF_FUNC KDF_get_ikev2_kdf(void);


#ifdef __cplusplus
}
#endif
#endif

