/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/socket.h>
#include <gmssl/error.h>

#ifdef WIN32
#include <windows.h>
#endif


static int tls_socket_should_print_error(int err, int is_read)
{
	tls_socket_err_t type = tls_socket_get_error_type(err, is_read);
	return type != TLS_SOCKET_ERR_WANT_READ
		&& type != TLS_SOCKET_ERR_WANT_WRITE
		&& type != TLS_SOCKET_ERR_INTERRUPTED;
}

#ifdef WIN32

int tls_socket_get_error(void)
{
	return WSAGetLastError();
}

tls_socket_err_t tls_socket_get_error_type(int err, int is_read)
{
	switch (err) {
	case 0:
		return TLS_SOCKET_ERR_NONE;
	case WSAEWOULDBLOCK:
	case WSAEINPROGRESS:
	case WSAEALREADY:
		return is_read ? TLS_SOCKET_ERR_WANT_READ : TLS_SOCKET_ERR_WANT_WRITE;
	case WSAEINTR:
		return TLS_SOCKET_ERR_INTERRUPTED;
	case WSAECONNRESET:
		return TLS_SOCKET_ERR_RESET;
	case WSAECONNABORTED:
	case WSAESHUTDOWN:
	case WSAENOTCONN:
		return TLS_SOCKET_ERR_CLOSED;
	case WSAETIMEDOUT:
		return TLS_SOCKET_ERR_TIMEOUT;
	case WSAEINVAL:
	case WSAENOTSOCK:
		return TLS_SOCKET_ERR_INVAL;
	default:
		return TLS_SOCKET_ERR_SYSTEM;
	}
}

const char *tls_socket_get_error_string(int err)
{
	static char buf[256];
	DWORD len;

	len = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, err, 0, buf, sizeof(buf), NULL);
	if (len > 0) {
		while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n')) {
			buf[--len] = 0;
		}
		return buf;
	}
	snprintf(buf, sizeof(buf), "Windows socket error %d", err);
	return buf;
}

void tls_socket_print_error(const char *func, int err)
{
	error_print_msg("%s error: %d (%s)\n",
		func ? func : "socket", err, tls_socket_get_error_string(err));
}

tls_socket_t tls_socket_invalid(void)
{
	return INVALID_SOCKET;
}

int tls_socket_is_valid(tls_socket_t sock)
{
	return sock != INVALID_SOCKET;
}

int tls_socket_lib_init(void)
{
	WORD wVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	int err;

	if ((err = WSAStartup(wVersion, &wsaData)) != 0) {
		tls_socket_print_error("WSAStartup", err);
		return -1;
	}
	return 1;
}

int tls_socket_lib_cleanup(void)
{
	if (WSACleanup() != 0) {
		tls_socket_print_error("WSACleanup", tls_socket_get_error());
		return -1;
	}
	return 1;
}

tls_ret_t tls_socket_send(tls_socket_t sock, const void *buf, size_t len, int flags)
{
	tls_ret_t ret;

	if (len > INT_MAX) {
		WSASetLastError(WSAEMSGSIZE);
		tls_socket_print_error("send", WSAEMSGSIZE);
		return SOCKET_ERROR;
	}
	ret = send(sock, (const char *)buf, (int)len, flags);
	if (ret == SOCKET_ERROR) {
		int err = tls_socket_get_error();
		if (tls_socket_should_print_error(err, 0)) {
			tls_socket_print_error("send", err);
		}
	}
	return ret;
}

tls_ret_t tls_socket_recv(tls_socket_t sock, void *buf, size_t len, int flags)
{
	tls_ret_t ret;

	if (len > INT_MAX) {
		WSASetLastError(WSAEMSGSIZE);
		tls_socket_print_error("recv", WSAEMSGSIZE);
		return SOCKET_ERROR;
	}
	ret = recv(sock, (char *)buf, (int)len, flags);
	if (ret == SOCKET_ERROR) {
		int err = tls_socket_get_error();
		if (tls_socket_should_print_error(err, 1)) {
			tls_socket_print_error("recv", err);
		}
	}
	return ret;
}

int tls_socket_close(tls_socket_t sock)
{
	int ret = closesocket(sock);
	if (ret == SOCKET_ERROR) {
		tls_socket_print_error("closesocket", tls_socket_get_error());
	}
	return ret;
}

void tls_socket_wait(void)
{
	Sleep(1);
}

int tls_socket_set_nonblocking(tls_socket_t sock, int nonblock)
{
	u_long mode = nonblock ? 1 : 0;
	if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
		tls_socket_print_error("ioctlsocket", tls_socket_get_error());
		return -1;
	}
	return 1;
}

int tls_socket_create(tls_socket_t *sock, int af, int type, int protocol)
{
	if (!sock) {
		error_print();
		return -1;
	}
	// INVALID_SOCKET == -1
	if ((*sock = socket(af, type, protocol)) == INVALID_SOCKET) {
		tls_socket_print_error("socket", tls_socket_get_error());
		return -1;
	}
	return 1;
}

int tls_socket_connect(tls_socket_t sock, const struct sockaddr_in *addr)
{
	int addr_len = (int)sizeof(struct sockaddr_in);
	if (connect(sock, (const struct sockaddr *)addr, addr_len) == SOCKET_ERROR) {
		int err = tls_socket_get_error();
		if (tls_socket_should_print_error(err, 0)) {
			tls_socket_print_error("connect", err);
		}
		return -1;
	}
	return 1;
}

int tls_socket_bind(tls_socket_t sock, const struct sockaddr_in *addr)
{
	int addr_len = (int)sizeof(struct sockaddr_in);
	if (bind(sock, (const struct sockaddr *)addr, addr_len) == SOCKET_ERROR) {
		tls_socket_print_error("bind", tls_socket_get_error());
		return -1;
	}
	return 1;
}

int tls_socket_listen(tls_socket_t sock, int backlog)
{
	if (listen(sock, backlog) == SOCKET_ERROR) {
		tls_socket_print_error("listen", tls_socket_get_error());
		return -1;
	}
	return 1;
}

int tls_socket_accept(tls_socket_t sock, struct sockaddr_in *addr, tls_socket_t *conn_sock)
{
	int addr_len = (int)sizeof(struct sockaddr_in);
	if ((*conn_sock = accept(sock, (struct sockaddr *)addr, &addr_len)) == INVALID_SOCKET) {
		int err = tls_socket_get_error();
		if (tls_socket_should_print_error(err, 1)) {
			tls_socket_print_error("accept", err);
		}
		return -1;
	}
	return 1;
}

#else

int tls_socket_get_error(void)
{
	return errno;
}

tls_socket_err_t tls_socket_get_error_type(int err, int is_read)
{
	switch (err) {
	case 0:
		return TLS_SOCKET_ERR_NONE;
	case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
	case EWOULDBLOCK:
#endif
	case EINPROGRESS:
	case EALREADY:
		return is_read ? TLS_SOCKET_ERR_WANT_READ : TLS_SOCKET_ERR_WANT_WRITE;
	case EINTR:
		return TLS_SOCKET_ERR_INTERRUPTED;
	case ECONNRESET:
		return TLS_SOCKET_ERR_RESET;
	case ECONNABORTED:
	case EPIPE:
	case ENOTCONN:
		return TLS_SOCKET_ERR_CLOSED;
	case ETIMEDOUT:
		return TLS_SOCKET_ERR_TIMEOUT;
	case EINVAL:
	case EBADF:
	case ENOTSOCK:
		return TLS_SOCKET_ERR_INVAL;
	default:
		return TLS_SOCKET_ERR_SYSTEM;
	}
}

const char *tls_socket_get_error_string(int err)
{
	return strerror(err);
}

void tls_socket_print_error(const char *func, int err)
{
	error_print_msg("%s error: %d (%s)\n",
		func ? func : "socket", err, tls_socket_get_error_string(err));
}

tls_socket_t tls_socket_invalid(void)
{
	return -1;
}

int tls_socket_is_valid(tls_socket_t sock)
{
	return sock >= 0;
}

int tls_socket_lib_init(void)
{
	return 1;
}

int tls_socket_lib_cleanup(void)
{
	return 1;
}

tls_ret_t tls_socket_send(tls_socket_t sock, const void *buf, size_t len, int flags)
{
	tls_ret_t ret = send(sock, buf, len, flags);
	if (ret < 0) {
		int err = tls_socket_get_error();
		if (tls_socket_should_print_error(err, 0)) {
			tls_socket_print_error("send", err);
		}
	}
	return ret;
}

tls_ret_t tls_socket_recv(tls_socket_t sock, void *buf, size_t len, int flags)
{
	tls_ret_t ret = recv(sock, buf, len, flags);
	if (ret < 0) {
		int err = tls_socket_get_error();
		if (tls_socket_should_print_error(err, 1)) {
			tls_socket_print_error("recv", err);
		}
	}
	return ret;
}

int tls_socket_close(tls_socket_t sock)
{
	int ret = close(sock);
	if (ret < 0) {
		tls_socket_print_error("close", tls_socket_get_error());
	}
	return ret;
}

void tls_socket_wait(void)
{
	usleep(1000);
}

int tls_socket_set_nonblocking(tls_socket_t sock, int nonblock)
{
	int flags;

	if ((flags = fcntl(sock, F_GETFL)) < 0) {
		tls_socket_print_error("fcntl(F_GETFL)", tls_socket_get_error());
		return -1;
	}
	if (nonblock) {
		flags |= O_NONBLOCK;
	} else {
		flags &= ~O_NONBLOCK;
	}
	if (fcntl(sock, F_SETFL, flags) < 0) {
		tls_socket_print_error("fcntl(F_SETFL)", tls_socket_get_error());
		return -1;
	}
	return 1;
}

int tls_socket_create(tls_socket_t *sock, int af, int type, int protocol)
{
	if (!sock) {
		error_print();
		return -1;
	}
	if ((*sock = socket(af, type, protocol)) == -1) {
		tls_socket_print_error("socket", tls_socket_get_error());
		return -1;
	}
	return 1;
}

int tls_socket_connect(tls_socket_t sock, const struct sockaddr_in *addr)
{
	socklen_t addr_len = sizeof(struct sockaddr_in);
	if (connect(sock, (const struct sockaddr *)addr, addr_len) == -1) {
		int err = tls_socket_get_error();
		if (tls_socket_should_print_error(err, 0)) {
			tls_socket_print_error("connect", err);
		}
		return -1;
	}
	return 1;
}

int tls_socket_bind(tls_socket_t sock, const struct sockaddr_in *addr)
{
	socklen_t addr_len = (socklen_t)sizeof(struct sockaddr_in);
	if (bind(sock, (const struct sockaddr *)addr, addr_len) == -1) {
		tls_socket_print_error("bind", tls_socket_get_error());
		return -1;
	}
	return 1;
}

int tls_socket_listen(tls_socket_t sock, int backlog)
{
	if (listen(sock, backlog) == -1) {
		tls_socket_print_error("listen", tls_socket_get_error());
		return -1;
	}
	return 1;
}

int tls_socket_accept(tls_socket_t sock, struct sockaddr_in *addr, tls_socket_t *conn_sock)
{
	socklen_t addr_len = (socklen_t)sizeof(struct sockaddr_in);
	if ((*conn_sock = accept(sock, (struct sockaddr *)addr, &addr_len)) == -1) {
		int err = tls_socket_get_error();
		if (tls_socket_should_print_error(err, 1)) {
			tls_socket_print_error("accept", err);
		}
		return -1;
	}
	return 1;
}
#endif
