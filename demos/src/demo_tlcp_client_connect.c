#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <gmssl/tls.h>
#include <gmssl/error.h>
#define TLS_DEFAULT_VERIFY_DEPTH	4

int main(int argc, char *argv[])
{
    int ret = -1;
    char *prog = argv[0];
    const int cipher = TLS_cipher_ecc_sm4_cbc_sm3;
    struct hostent *hp;
    struct sockaddr_in server;
    int sock;
    TLS_CTX ctx;
    TLS_CONNECT conn;
    char request[1024];
    uint8_t buf[16800];
    char *p;
    size_t len;
	
    //证书和密钥使用/demos/scripts/tlcp_server.sh生成
    char* cacertfile="rootcacert.pem";
    char* certfile="clientcert.pem";
    char* keyfile="clientkey.pem";
    char *pass = "1234";
    if(argc < 3)
    {
    	fprintf(stderr,"usage %s ip port \n",argv[0]);
    	return -1;
    }
    server.sin_family = AF_INET;
    server.sin_port = htons(atoi(argv[2]));
    server.sin_addr.s_addr = inet_addr(argv[1]);
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        printf("创建socket错误");
        goto end;
    }
    if (connect(sock, (struct sockaddr *)&server , sizeof(server)) < 0) {//去连接服务器
        perror("connect");
        printf("socket连接失败");
        goto end;
    }


	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));

	tls_ctx_init(&ctx, TLS_protocol_tlcp, TLS_client_mode);
	tls_ctx_set_cipher_suites(&ctx, &cipher, 1);

	if (cacertfile) {
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, TLS_DEFAULT_VERIFY_DEPTH) != 1) {
			fprintf(stderr, "%s: context init error\n", prog);
			goto end;
		}
	}
	if (certfile) {
		if (tls_ctx_set_certificate_and_key(&ctx, certfile, keyfile, pass) != 1) {
			fprintf(stderr, "%s: context init error\n", prog);
			goto end;
		}
	}

    tls_init(&conn, &ctx);
	tls_set_socket(&conn, sock);


    if(tls_do_handshake(&conn) == 1)
    {
        return 0;
    }
	else {//握手
		fprintf(stderr, "%s: error\n", prog);
		goto end;
	}
end:
    close(sock);
	tls_ctx_cleanup(&ctx);
	tls_cleanup(&conn);
    return 0;
}
