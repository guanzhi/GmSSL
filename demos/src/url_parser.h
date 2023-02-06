/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef URL_PARSER_H
#define URL_PARSER_H

#define URL_PARSER_VERSION  0x00000300	/* 0.0.3 */

typedef struct url_components {
	char *scheme;
	char *user;
	char *password;
	char *host;
	int  port;
	char *path;
	char *query;
	char *fragment;
} URL_COMPONENTS;

extern URL_COMPONENTS *parse_url(const char *url);
extern void free_url_components(URL_COMPONENTS *c);

#endif
