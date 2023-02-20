/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_HTTP_H
#define GMSSL_HTTP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


int http_parse_uri(const char *uri, char host[128], int *port, char path[256]);
int http_parse_response(char *buf, size_t buflen, uint8_t **content, size_t *contentlen, size_t *left);
int http_get(const char *uri, uint8_t *buf, size_t *contentlen, size_t buflen);


#ifdef __cplusplus
}
#endif
#endif
