/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <gmssl/error.h>


int file_size(FILE *fp, size_t *size)
{
	int fd;
	struct stat st;

#ifdef WIN32
	fd = _fileno(fp);
#else
	fd = fileno(fp);
#endif
	if (fstat(fd, &st) < 0) {
		error_print();
		return -1;
	}
	*size = st.st_size;
	return 1;
}
