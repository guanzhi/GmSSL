/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>
#include <gmssl/passwd.h>

#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <termios.h>
#endif


static int gmssl_password_read_line(FILE *in, FILE *out, const char *prompt, char *pass, size_t passlen)
{
	size_t len;
	int too_long = 0;
	int ch;

	if (prompt && prompt[0]) {
		fputs(prompt, out);
	} else {
		fputs("Password: ", out);
	}
	fflush(out);

	if (!fgets(pass, (int)passlen, in)) {
		error_print();
		pass[0] = '\0';
		return -1;
	}

	len = strlen(pass);
	if (len > 0 && pass[len - 1] == '\n') {
		pass[--len] = '\0';
		if (len > 0 && pass[len - 1] == '\r') {
			pass[--len] = '\0';
		}
	} else if (!feof(in)) {
		too_long = 1;
		while ((ch = fgetc(in)) != EOF && ch != '\n') {
		}
	}

	if (too_long) {
		gmssl_secure_clear(pass, passlen);
		error_print();
		return -1;
	}

	return 1;
}

static int gmssl_password_read(FILE *in, FILE *out, const char *prompt,
	char *pass, size_t passlen, int do_confirm)
{
	char *confirm = NULL;
	int ret = -1;

	ret = gmssl_password_read_line(in, out, prompt, pass, passlen);
	fputc('\n', out);
	fflush(out);
	if (ret != 1) {
		goto end;
	}

	if (do_confirm) {
		if (!(confirm = malloc(passlen))) {
			error_print();
			goto end;
		}
		ret = gmssl_password_read_line(in, out, "Confirm: ", confirm, passlen);
		fputc('\n', out);
		fflush(out);
		if (ret != 1) {
			goto end;
		}
		if (strcmp(pass, confirm) != 0) {
			error_print();
			goto end;
		}
	}

	ret = 1;

end:
	if (ret != 1) {
		gmssl_secure_clear(pass, passlen);
	}
	if (confirm) {
		gmssl_secure_clear(confirm, passlen);
		free(confirm);
	}
	return ret;
}

#if defined(_WIN32)

int gmssl_read_password(const char *prompt, char *pass, size_t passlen, int do_confirm)
{
	FILE *in = NULL;
	FILE *out = NULL;
	HANDLE in_handle;
	DWORD old_mode;
	DWORD new_mode;
	int ret = -1;

	if (!pass || passlen < 2 || passlen > INT_MAX) {
		error_print();
		return -1;
	}
	pass[0] = '\0';

	if (!(in = fopen("CONIN$", "r")) || !(out = fopen("CONOUT$", "w"))) {
		error_print();
		goto end;
	}

	in_handle = (HANDLE)_get_osfhandle(_fileno(in));
	if (in_handle == INVALID_HANDLE_VALUE
		|| !GetConsoleMode(in_handle, &old_mode)) {
		error_print();
		goto end;
	}

	new_mode = old_mode & ~ENABLE_ECHO_INPUT;
	if (!SetConsoleMode(in_handle, new_mode)) {
		error_print();
		goto end;
	}

	ret = gmssl_password_read(in, out, prompt, pass, passlen, do_confirm);

	if (!SetConsoleMode(in_handle, old_mode)) {
		error_print();
		ret = -1;
	}

end:
	if (in) fclose(in);
	if (out) fclose(out);
	if (ret != 1 && pass) gmssl_secure_clear(pass, passlen);
	return ret;
}

#else

int gmssl_read_password(const char *prompt, char *pass, size_t passlen, int do_confirm)
{
	FILE *tty = NULL;
	int fd;
	struct termios old_termios;
	struct termios new_termios;
	int ret = -1;

	if (!pass || passlen < 2 || passlen > INT_MAX) {
		error_print();
		return -1;
	}
	pass[0] = '\0';

	if (!(tty = fopen("/dev/tty", "r+"))) {
		error_print();
		goto end;
	}

	fd = fileno(tty);
	if (tcgetattr(fd, &old_termios) < 0) {
		error_print();
		goto end;
	}

	new_termios = old_termios;
	new_termios.c_lflag &= (tcflag_t)~ECHO;
	if (tcsetattr(fd, TCSAFLUSH, &new_termios) < 0) {
		error_print();
		goto end;
	}

	ret = gmssl_password_read(tty, tty, prompt, pass, passlen, do_confirm);

	if (tcsetattr(fd, TCSAFLUSH, &old_termios) < 0) {
		error_print();
		ret = -1;
	}

end:
	if (tty) fclose(tty);
	if (ret != 1 && pass) gmssl_secure_clear(pass, passlen);
	return ret;
}

#endif
