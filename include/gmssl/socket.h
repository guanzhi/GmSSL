/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_SOCKET_H
#define GMSSL_SOCKET_H

#include <string.h>
#include <stdint.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif



#ifdef WIN32
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#include <winsock2.h>

typedef SOCKET tls_socket_t;
typedef int tls_ret_t;
typedef int tls_socklen_t;

#else

#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>

typedef int tls_socket_t;
typedef ssize_t tls_ret_t;
typedef socklen_t tls_socklen_t;

#endif

typedef enum {
	TLS_SOCKET_ERR_NONE = 0,
	TLS_SOCKET_ERR_WANT_READ,
	TLS_SOCKET_ERR_WANT_WRITE,
	TLS_SOCKET_ERR_INTERRUPTED,
	TLS_SOCKET_ERR_CLOSED,
	TLS_SOCKET_ERR_RESET,
	TLS_SOCKET_ERR_TIMEOUT,
	TLS_SOCKET_ERR_INVAL,
	TLS_SOCKET_ERR_SYSTEM,
} tls_socket_err_t;

int tls_socket_lib_init(void);
int tls_socket_lib_cleanup(void);
tls_ret_t tls_socket_send(tls_socket_t sock, const void *buf, size_t len, int flags);
tls_ret_t tls_socket_recv(tls_socket_t sock, void *buf, size_t len, int flags);
int tls_socket_close(tls_socket_t sock);
void tls_socket_wait(void);
int tls_socket_get_error(void);
tls_socket_err_t tls_socket_get_error_type(int err, int is_read);
const char *tls_socket_get_error_string(int err);
void tls_socket_print_error(const char *func, int err);
int tls_socket_set_nonblocking(tls_socket_t sock, int nonblock);
tls_socket_t tls_socket_invalid(void);
int tls_socket_is_valid(tls_socket_t sock);
int tls_socket_create(tls_socket_t *sock, int af, int type, int protocl);
int tls_socket_get_addr(const char *host, int port, struct sockaddr_in *addr);
int tls_socket_connect(tls_socket_t sock, const struct sockaddr_in *addr);
int tls_socket_bind(tls_socket_t sock, const struct sockaddr_in *addr);
int tls_socket_listen(tls_socket_t sock, int backlog);
int tls_socket_accept(tls_socket_t sock, struct sockaddr_in *addr, tls_socket_t *conn_sock);


#ifdef __cplusplus
}
#endif
#endif
