



int ssl_init(void)
{
	// 不需要这个函数
	return 1;
}

typedef struct {
} SSL_CTX;


// nginx中用的是PEM

int ssl_use_certificate()
{
}

int ssl_use_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords)
{
}


ngx_ssl_ciphers			SSL_CTX_set_cipher_list

ngx_ssl_client_certificate	SSL_CTX_set_verify
				SSL_CTX_set_verify_depth
				SSL_CTX_load_verify_locations
				SSL_load_client_CA_file

ngx_ssl_trusted_certificate	SSL_CTX_set_verify
				SSL_CTX_set_verify_depth
	SSL_CTX_load_verify_locations
