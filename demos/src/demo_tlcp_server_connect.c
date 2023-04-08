#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/tls.h>
#include <gmssl/error.h>
#include <gmssl/pem.h>

int main(int argc,char *argv[]){

    int ret = 1;
	char *prog = argv[0];
	char *signpass = "1234";
	char *encpass = "1234";

	int server_ciphers[] = { TLS_cipher_ecc_sm4_cbc_sm3, };
	uint8_t verify_buf[4096];

	TLS_CTX ctx;
	TLS_CONNECT conn;
	char buf[1600] = {0};
	size_t len = sizeof(buf);

	int sock;
	struct sockaddr_in server_addr;//服务端地址
	struct sockaddr_in client_addr;//客户端地址
	socklen_t client_addrlen;
	int conn_sock;

	//证书和密钥使用/demos/scripts/tlcp_server.sh生成
	char* certfile="double_certs.pem";
	char* signkeyfile="signkey.pem";
	char* enckeyfile="enckey.pem";
	char* cacertfile="cacert.pem";


	if(argc < 3)
    {
    	fprintf(stderr,"usage %s ip port \n",argv[0]);
    	return -1;
    }

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));

	if (tls_ctx_init(&ctx, TLS_protocol_tlcp, TLS_server_mode) != 1
		|| tls_ctx_set_cipher_suites(&ctx, server_ciphers, sizeof(server_ciphers)/sizeof(int)) != 1
		|| tls_ctx_set_tlcp_server_certificate_and_keys(&ctx, certfile, signkeyfile, signpass, enckeyfile, encpass) != 1) {
		error_print();
		return -1;
	}
	if (cacertfile) {
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, TLS_DEFAULT_VERIFY_DEPTH) != 1) {
			error_print();
			return -1;
		}
	}
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		error_print();
		return 1;
	}

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(argv[2]));
    server_addr.sin_addr.s_addr = inet_addr(argv[1]);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        error_print();
        perror("tlcp_accept: bind: ");
    }

    puts("start listen ...\n");
    listen(sock, 1);
    client_addrlen = sizeof(client_addr);

    if ((conn_sock = accept(sock, (struct sockaddr *)&client_addr, &client_addrlen)) < 0) {
        error_print();
    }

    puts("socket connected\n");
    printf("client ip : %s\nport %d\n",inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));


	if (tls_init(&conn, &ctx) != 1
		|| tls_set_socket(&conn, conn_sock) != 1) {
		error_print();
		return -1;
	}
	printf("tlcp_init finished\n");
	if (tls_do_handshake(&conn) == 1) {
		return 0;
	}	
	else {
		error_print(); 
		return -1;
	}

	return 0;
}
