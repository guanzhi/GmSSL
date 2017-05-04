#ifndef LIBBASE58_H
#define LIBBASE58_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern bool base58_decode(const char *b58, size_t b58sz, void *bin, size_t *binsz);

extern bool base58_encode(const void *bin, size_t binsz, char *b58, size_t *b58sz);
#ifdef __cplusplus
}
#endif

#endif

