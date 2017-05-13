#ifndef HEADER_BASE58_H
#define HEADER_BASE58_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool base58_decode(const char *b58, size_t b58sz, void *bin, size_t *binszp);
bool base58_encode(const void *data, size_t binsz, char *b58, size_t *b58sz);

#endif
