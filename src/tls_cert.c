/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/tls.h>


static int tls_cert_issuer_match_subject(const uint8_t *cert, size_t certlen,
	const uint8_t *issuer_cert, size_t issuer_certlen)
{
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *subject;
	size_t subject_len;

	if (x509_cert_get_issuer(cert, certlen, &issuer, &issuer_len) != 1
		|| x509_cert_get_subject(issuer_cert, issuer_certlen, &subject, &subject_len) != 1
		|| x509_name_equ(issuer, issuer_len, subject, subject_len) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

static int tls_cert_chain_check_order(const uint8_t *certs, size_t certslen)
{
	const uint8_t *cert;
	size_t certlen;

	if (!certs || !certslen) {
		error_print();
		return -1;
	}
	if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1) {
		error_print();
		return -1;
	}

	while (certslen) {
		const uint8_t *issuer_cert;
		size_t issuer_certlen;

		if (x509_cert_from_der(&issuer_cert, &issuer_certlen, &certs, &certslen) != 1
			|| tls_cert_issuer_match_subject(cert, certlen, issuer_cert, issuer_certlen) != 1) {
			error_print();
			return -1;
		}
		cert = issuer_cert;
		certlen = issuer_certlen;
	}

	return 1;
}

static int tlcp_cert_chain_check_order(const uint8_t *certs, size_t certslen)
{
	const uint8_t *sign_cert;
	size_t sign_certlen;
	const uint8_t *enc_cert;
	size_t enc_certlen;
	const uint8_t *ca_cert;
	size_t ca_certlen;

	if (!certs || !certslen) {
		error_print();
		return -1;
	}
	if (x509_cert_from_der(&sign_cert, &sign_certlen, &certs, &certslen) != 1
		|| x509_cert_from_der(&enc_cert, &enc_certlen, &certs, &certslen) != 1) {
		error_print();
		return -1;
	}
	if (!certslen) {
		return 1;
	}

	if (x509_cert_from_der(&ca_cert, &ca_certlen, &certs, &certslen) != 1
		|| tls_cert_issuer_match_subject(sign_cert, sign_certlen, ca_cert, ca_certlen) != 1
		|| tls_cert_issuer_match_subject(enc_cert, enc_certlen, ca_cert, ca_certlen) != 1) {
		error_print();
		return -1;
	}

	while (certslen) {
		const uint8_t *issuer_cert;
		size_t issuer_certlen;

		if (x509_cert_from_der(&issuer_cert, &issuer_certlen, &certs, &certslen) != 1
			|| tls_cert_issuer_match_subject(ca_cert, ca_certlen, issuer_cert, issuer_certlen) != 1) {
			error_print();
			return -1;
		}
		ca_cert = issuer_cert;
		ca_certlen = issuer_certlen;
	}

	return 1;
}

int tls_ctx_add_certificate_list_and_key(TLS_CTX *ctx, const char *chainfile,
	const uint8_t *entity_status_request_ocsp_response, size_t entity_status_request_ocsp_response_len, // optional
	const uint8_t *entity_signed_certificate_timestamp_list, size_t entity_signed_certificate_timestamp_list_len, // optional
	const char *keyfile, const char *keypass)
{
	uint8_t *cert_chain;
	size_t cert_chain_len;
	uint8_t *certs;
	size_t certslen;
	FILE *certfp = NULL;
	const uint8_t *cert;
	size_t certlen;
	X509_KEY public_key;
	size_t key_idx;
	FILE *keyfp = NULL;

	uint8_t *ocsp_responses;
	size_t ocsp_responses_len;
	uint8_t *sct_lists;
	size_t sct_lists_len;

	if (!ctx || !chainfile || !keyfile || !keypass) {
		error_print();
		return -1;
	}

	// status_request
	ocsp_responses_len = ctx->status_request_ocsp_responses_len;
	tls_uint24array_to_bytes(
		entity_status_request_ocsp_response,
		entity_status_request_ocsp_response_len,
		NULL, &ocsp_responses_len);
	if (ocsp_responses_len > sizeof(ctx->status_request_ocsp_responses)) {
		error_print();
		return -1;
	}
	ocsp_responses = ctx->status_request_ocsp_responses;
	tls_uint24array_to_bytes(
		entity_status_request_ocsp_response,
		entity_status_request_ocsp_response_len,
		&ocsp_responses,
		&ctx->status_request_ocsp_responses_len);

	// signed_certificate_timestamp
	sct_lists_len = ctx->signed_certificate_timestamp_lists_len;
	tls_uint16array_to_bytes(
		entity_signed_certificate_timestamp_list,
		entity_signed_certificate_timestamp_list_len,
		NULL, &sct_lists_len);
	if (sct_lists_len > sizeof(ctx->signed_certificate_timestamp_lists)) {
		error_print();
		return -1;
	}
	sct_lists = ctx->signed_certificate_timestamp_lists;
	tls_uint16array_to_bytes(
		entity_signed_certificate_timestamp_list,
		entity_signed_certificate_timestamp_list_len,
		&sct_lists, &ctx->signed_certificate_timestamp_lists_len);


	// add cert_chain to ctx->cert_chains
	if (sizeof(ctx->cert_chains) <= ctx->cert_chains_len + tls_uint24_size()) {
		error_print();
		return -1;
	}
	if (!(certfp = fopen(chainfile, "r"))) {
		error_print();
		return -1;
	}
	cert_chain = ctx->cert_chains + ctx->cert_chains_len ;
	certs = cert_chain + tls_uint24_size();
	if (x509_certs_from_pem(certs, &certslen,
		sizeof(ctx->cert_chains) - ctx->cert_chains_len - tls_uint24_size(), certfp) != 1) {
		fclose(certfp);
		error_print();
		return -1;
	}
	if (tls_cert_chain_check_order(certs, certslen) != 1) {
		fclose(certfp);
		error_print();
		return -1;
	}

	// add private key to ctx->x509_keys
	if (sizeof(ctx->x509_keys)/sizeof(ctx->x509_keys[0]) <= ctx->x509_keys_cnt) {
		fclose(certfp);
		error_print();
		return -1;
	}
	key_idx = ctx->x509_keys_cnt;
	if (x509_certs_get_cert_by_index(certs, certslen, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1) {
		fclose(certfp);
		error_print();
		return -1;
	}
	if (public_key.algor == OID_ec_public_key) {
		if (!(keyfp = fopen(keyfile, "r"))) {
			fclose(certfp);
			error_print();
			return -1;
		}
	} else {
		if (!(keyfp = fopen(keyfile, "rb+"))) {
			fclose(certfp);
			error_print();
			return -1;
		}
	}
	if (x509_private_key_from_file(&ctx->x509_keys[key_idx], public_key.algor, keypass, keyfp) != 1) {
		fclose(certfp);
		fclose(keyfp);
		error_print();
		return -1;
	}
	if (x509_public_key_equ(&ctx->x509_keys[key_idx], &public_key) != 1) {
		x509_key_cleanup(&ctx->x509_keys[key_idx]);
		fclose(certfp);
		fclose(keyfp);
		error_print();
		return -1;
	}
	cert_chain_len = 0;
	tls_uint24_to_bytes((uint24_t)certslen, &cert_chain, &cert_chain_len);
	cert_chain_len += certslen;
	ctx->cert_chains_len += cert_chain_len;
	ctx->x509_keys_cnt++;

	// TODO: if the second cert is entity's sm2 encryption cert, try to read private key from keyfp

	fclose(certfp);
	fclose(keyfp);
	return 1;
}

int tls_ctx_add_certificate_chain_and_key(TLS_CTX *ctx, const char *chainfile,
	const char *keyfile, const char *keypass)
{
	if (tls_ctx_add_certificate_list_and_key(ctx, chainfile, NULL, 0, NULL, 0, keyfile, keypass) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


int tls_ctx_set_certificate_and_key(TLS_CTX *ctx, const char *chainfile,
	const char *keyfile, const char *keypass)
{
	if (!ctx || !chainfile || !keyfile || !keypass) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(ctx->protocol)) {
		error_print();
		return -1;
	}
	if (ctx->cert_chains_len || ctx->x509_keys_cnt) {
		error_print();
		return -1;
	}
	if (tls_ctx_add_certificate_chain_and_key(ctx, chainfile, keyfile, keypass) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int tlcp_ctx_add_certificate_and_keys(TLS_CTX *ctx, const char *chainfile,
	const char *keyfile, const char *keypass)
{
	int ret = -1;
	const int algor = OID_ec_public_key;
	const int algor_param = OID_sm2;
	uint8_t *cert_chain;
	uint8_t *certs;
	size_t certslen;
	size_t cert_chains_len;
	size_t key_idx;
	FILE *certfp = NULL;
	FILE *keyfp = NULL;

	const uint8_t *cert;
	size_t certlen;
	X509_KEY public_key;


	if (!ctx || !chainfile || !keyfile || !keypass) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(ctx->protocol)) {
		error_print();
		return -1;
	}
	if (ctx->protocol != TLS_protocol_tlcp) {
		error_print();
		return -1;
	}
	if (ctx->x509_keys_cnt >= sizeof(ctx->x509_keys)/sizeof(ctx->x509_keys[0])) {
		error_print();
		return -1;
	}
	key_idx = ctx->x509_keys_cnt;

	if (sizeof(ctx->cert_chains) <= ctx->cert_chains_len + tls_uint24_size()) {
		error_print();
		return -1;
	}
	if (!(certfp = fopen(chainfile, "r"))) {
		error_print();
		goto end;
	}
	cert_chain = ctx->cert_chains + ctx->cert_chains_len;
	certs = cert_chain + tls_uint24_size();
	if (x509_certs_from_pem(certs, &certslen,
		sizeof(ctx->cert_chains) - ctx->cert_chains_len - tls_uint24_size(), certfp) != 1) {
		error_print();
		goto end;
	}
	if (tlcp_cert_chain_check_order(certs, certslen) != 1) {
		error_print();
		goto end;
	}
	cert_chains_len = 0;
	tls_uint24_to_bytes((uint24_t)certslen, &cert_chain, &cert_chains_len);
	cert_chains_len += certslen;

	// load sign key
	if (!(keyfp = fopen(keyfile, "r"))) {
		error_print();
		goto end;
	}
	if (x509_private_key_from_file(&ctx->x509_keys[key_idx], algor, keypass, keyfp) != 1) {
		error_print();
		goto end;
	}
	if (x509_certs_get_cert_by_index(certs, certslen, 0, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1) {
		error_print();
		goto end;
	}
	if (public_key.algor != algor || public_key.algor_param != algor_param
		|| x509_public_key_equ(&ctx->x509_keys[key_idx], &public_key) != 1) {
		error_print();
		goto end;
	}

	// load enc key
	if (x509_private_key_from_file(&ctx->enc_keys[key_idx], algor, keypass, keyfp) != 1) {
		error_print();
		goto end;
	}
	if (x509_certs_get_cert_by_index(certs, certslen, 1, &cert, &certlen) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1) {
		error_print();
		goto end;
	}
	if (public_key.algor != algor || public_key.algor_param != algor_param
		|| x509_public_key_equ(&ctx->enc_keys[key_idx], &public_key) != 1) {
		error_print();
		goto end;
	}

	ctx->cert_chains_len += cert_chains_len;
	ctx->x509_keys_cnt++;
	ret = 1;

end:
	if (ret != 1) {
		x509_key_cleanup(&ctx->x509_keys[key_idx]);
		x509_key_cleanup(&ctx->enc_keys[key_idx]);
	}
	if (certfp) fclose(certfp);
	if (keyfp) fclose(keyfp);
	return ret;
}

int tlcp_ctx_add_server_certificate_and_keys(TLS_CTX *ctx, const char *chainfile,
	const char *keyfile, const char *keypass)
{
	if (!ctx || ctx->is_client) {
		error_print();
		return -1;
	}
	if (tlcp_ctx_add_certificate_and_keys(ctx, chainfile, keyfile, keypass) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tlcp_ctx_add_client_certificate_and_keys(TLS_CTX *ctx, const char *chainfile,
	const char *keyfile, const char *keypass)
{
	if (!ctx || !ctx->is_client) {
		error_print();
		return -1;
	}
	if (tlcp_ctx_add_certificate_and_keys(ctx, chainfile, keyfile, keypass) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_ctx_set_tlcp_server_certificate_and_keys(TLS_CTX *ctx, const char *chainfile,
	const char *keyfile, const char *keypass)
{
	if (!ctx || ctx->cert_chains_len || ctx->x509_keys_cnt) {
		error_print();
		return -1;
	}
	if (tlcp_ctx_add_server_certificate_and_keys(ctx, chainfile,
		keyfile, keypass) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_ctx_set_tlcp_client_certificate_and_keys(TLS_CTX *ctx, const char *chainfile,
	const char *keyfile, const char *keypass)
{
	if (!ctx || ctx->cert_chains_len || ctx->x509_keys_cnt) {
		error_print();
		return -1;
	}
	if (tlcp_ctx_add_client_certificate_and_keys(ctx, chainfile,
		keyfile, keypass) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_authorities_issued_certificate(const uint8_t *ca_names, size_t ca_names_len, const uint8_t *certs, size_t certslen)
{
	const uint8_t *cert;
	size_t certlen;
	const uint8_t *issuer;
	size_t issuer_len;


	//x509_certs_print(stderr, 0, 0, "cert_chain", certs, certslen);


	if (x509_certs_get_last(certs, certslen, &cert, &certlen) != 1
		|| x509_cert_get_issuer(cert, certlen, &issuer, &issuer_len) != 1) {
		error_print();
		return -1;
	}

	//x509_cert_print(stderr, 0, 0, "last cert", cert, certlen);

	//x509_name_print(stderr, 0, 0, "issuer", issuer, issuer_len);

	while (ca_names_len) {
		const uint8_t *p;
		size_t len;
		const uint8_t *name;
		size_t namelen;

		if (tls_uint16array_from_bytes(&p, &len, &ca_names, &ca_names_len) != 1) {
			error_print();
			return -1;
		}
		if (asn1_sequence_from_der(&name, &namelen, &p, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}

		//x509_name_print(stderr, 0, 0, "ca", name, namelen);


		if (x509_name_equ(name, namelen, issuer, issuer_len) == 1) {
			return 1;
		}
	}
	error_print();
	return 0;
}

int tls_cert_types_has_ecdsa_sign(const uint8_t *types, size_t types_len)
{
	return 1;
}

// 这个函数不是很好，直接提供的是一个文件名
int tls_ctx_set_ca_certificates(TLS_CTX *ctx, const char *cacertsfile, int depth)
{
	if (!ctx || !cacertsfile) {
		error_print();
		return -1;
	}
	if (depth < 0 || depth > TLS_MAX_VERIFY_DEPTH) {
		error_print();
		return -1;
	}
	if (!tls_protocol_name(ctx->protocol)) {
		error_print();
		return -1;
	}
	if (ctx->cacerts) {
		error_print();
		return -1;
	}
	if (x509_certs_new_from_file(&ctx->cacerts, &ctx->cacertslen, cacertsfile) != 1) {
		error_print();
		return -1;
	}
	if (ctx->cacertslen == 0) {
		error_print();
		return -1;
	}

	// 在读取CA证书的时候，提取了证书的名字
	if (tls_authorities_from_certs(ctx->ca_names, &ctx->ca_names_len, sizeof(ctx->ca_names),
		ctx->cacerts, ctx->cacertslen) != 1) {
		error_print();
		return -1;
	}
	if (tls_trusted_authorities_from_ca_names(ctx->trusted_authorities, &ctx->trusted_authorities_len,
		sizeof(ctx->trusted_authorities), ctx->ca_names, ctx->ca_names_len) != 1) {
		error_print();
		return -1;
	}

	ctx->verify_depth = depth;
	return 1;
}

int tls_authorities_from_certs(uint8_t *names, size_t *nameslen, size_t maxlen, const uint8_t *certs, size_t certslen)
{
	const uint8_t *cert;
	size_t certlen;
	const uint8_t *name;
	size_t namelen;

	*nameslen = 0;
	while (certslen) {
		size_t alen = 0;
		if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1
			|| x509_cert_get_subject(cert, certlen, &name, &namelen) != 1
			|| asn1_sequence_to_der(name, namelen, NULL, &alen) != 1) {
			error_print();
			return -1;
		}
		if (tls_uint16_size() + alen > maxlen) {
			error_print();
			return -1;
		}
		if (alen > UINT16_MAX) {
			error_print();
			return -1;
		}

		tls_uint16_to_bytes((uint16_t)alen, &names, nameslen);
		maxlen -= tls_uint16_size();

		if (asn1_sequence_to_der(name, namelen, &names, nameslen) != 1) {
			error_print();
			return -1;
		}
		maxlen -= alen;
	}
	return 1;
}



int tls12_cert_chains_select(const uint8_t *cert_chains, size_t cert_chains_len,
	const int *supported_groups, size_t supported_groups_cnt, // optional
	const int *signature_algorithms, size_t signature_algorithms_cnt, // optional
	const uint8_t *ca_names, size_t ca_names_len, // certificate_authorities optional
	const uint8_t *host_name, size_t host_name_len, // optional, only in ClientHello
	const uint8_t **certs, size_t *certs_len, size_t *certs_idx, int *prefered_sig_alg) // optional
{
	size_t i;

	if (!cert_chains || !cert_chains_len) {
		error_print();
		return -1;
	}

	for (i = 1; cert_chains_len; i++) {
		const uint8_t *cert_chain;
		size_t cert_chain_len;
		int sig_alg;
		int ret;

		if (tls_uint24array_from_bytes(&cert_chain, &cert_chain_len,
			&cert_chains, &cert_chains_len) != 1) {
			error_print();
			return -1;
		}

		if (certs) *certs = cert_chain;
		if (certs_len) *certs_len = cert_chain_len;
		if (certs_idx) *certs_idx = i;
		if (prefered_sig_alg) *prefered_sig_alg = sig_alg;
		return 1;
	}

	return 0;
}

