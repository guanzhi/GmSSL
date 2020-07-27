/* ====================================================================
 * Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <openssl/opensslconf.h>

# include "../ssl_locl.h"
# include "statem_locl.h"
# include "internal/constant_time_locl.h"
# include <openssl/buffer.h>
# include <openssl/rand.h>
# include <openssl/objects.h>
# include <openssl/evp.h>
# include <openssl/hmac.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
# include <openssl/bn.h>
# include <openssl/sm2.h>
# include <openssl/crypto.h>


static int gmtls_output_cert_chain(SSL *s, int *len, int a_idx, int k_idx)
{
	unsigned char *p;
	unsigned long l = *len;
	BUF_MEM *buf = s->init_buf;
	int i;
	STACK_OF(X509) *extra_certs;
	STACK_OF(X509) *chain = NULL;
	X509_STORE *chain_store;
	CERT_PKEY *a_cpk;
	CERT_PKEY *k_cpk;

	if (!BUF_MEM_grow_clean(buf, 10)) {
		SSLerr(SSL_F_GMTLS_OUTPUT_CERT_CHAIN, ERR_R_BUF_LIB);
		return 0;
	}

	a_cpk = &s->cert->pkeys[a_idx];
	k_cpk = &s->cert->pkeys[k_idx];

	if (a_cpk->chain)
		extra_certs = a_cpk->chain;
	else if (k_cpk->chain)
		extra_certs = k_cpk->chain;
	else
		extra_certs = s->ctx->extra_certs;

	if ((s->mode & SSL_MODE_NO_AUTO_CHAIN) || extra_certs)
		chain_store = NULL;
	else if (s->cert->chain_store)
		chain_store = s->cert->chain_store;
	else
		chain_store = s->ctx->cert_store;

	if (chain_store) {
		X509_STORE_CTX *xs_ctx = X509_STORE_CTX_new();

		if (xs_ctx == NULL) {
			SSLerr(SSL_F_GMTLS_OUTPUT_CERT_CHAIN, ERR_R_MALLOC_FAILURE);
			return (0);
		}
		if (!X509_STORE_CTX_init(xs_ctx, chain_store, a_cpk->x509, NULL)) {
			X509_STORE_CTX_free(xs_ctx);
			SSLerr(SSL_F_GMTLS_OUTPUT_CERT_CHAIN, ERR_R_X509_LIB);
			return (0);
		}
		/*
		* It is valid for the chain not to be complete (because normally we
		* don't include the root cert in the chain). Therefore we deliberately
		* ignore the error return from this call. We're not actually verifying
		* the cert - we're just building as much of the chain as we can
		*/
		(void)X509_verify_cert(xs_ctx);
		/* Don't leave errors in the queue */
		ERR_clear_error();
		chain = X509_STORE_CTX_get0_chain(xs_ctx);

		i = ssl_security_cert_chain(s, chain, NULL, 0);
		if (i != 1) {
			X509_STORE_CTX_free(xs_ctx);
			SSLerr(SSL_F_GMTLS_OUTPUT_CERT_CHAIN, i);
			return 0;
		}

#if 0
        OPENSSL_assert(s->cert->pkeys[a_idx].x509 != NULL);
        OPENSSL_assert(s->cert->pkeys[k_idx].x509 != NULL);
        X509_print_fp(stderr, s->cert->pkeys[a_idx].x509);
        X509_print_fp(stderr, s->cert->pkeys[k_idx].x509);
#endif

		/* add signing certificate */
		if (!ssl_add_cert_to_buf(buf, &l, s->cert->pkeys[a_idx].x509)) {
			return 0;
		}
		/* add key exchange certificate */
		if (!ssl_add_cert_to_buf(buf, &l, s->cert->pkeys[k_idx].x509)) {
			return 0;
		}
		/* add the following chain */
		for (i = 1; i < sk_X509_num(chain); i++) {
			X509 *x = sk_X509_value(chain, i);
			if (!ssl_add_cert_to_buf(buf, &l, x)) {
				X509_STORE_CTX_free(xs_ctx);
				return 0;
			}
		}
		X509_STORE_CTX_free(xs_ctx);

	} else {

		i = ssl_security_cert_chain(s, extra_certs, a_cpk->x509, 0);
		if (i != 1) {
			SSLerr(SSL_F_GMTLS_OUTPUT_CERT_CHAIN, i);
			return 0;
		}

		/* output sign cert and exch cert */
		if (!ssl_add_cert_to_buf(buf, &l, s->cert->pkeys[a_idx].x509)) {
			return 0;
		}
		if (!ssl_add_cert_to_buf(buf, &l, s->cert->pkeys[k_idx].x509)) {
			return 0;
		}
		/* output the following chain */
		for (i = 0; i < sk_X509_num(extra_certs); i++) {
			X509 *x = sk_X509_value(extra_certs, i);
			if (!ssl_add_cert_to_buf(buf, &l, x)) {
				return 0;
			}
		}
	}

	l -= 3 + SSL_HM_HEADER_LENGTH(s);
	p = ssl_handshake_start(s);
	l2n3(l, p);
	l += 3;

    *len = (int)l;
    return 1;
}

#define gmtls_construct_sm2_certs(s,l)	\
	gmtls_output_cert_chain(s,l,SSL_PKEY_SM2,SSL_PKEY_SM2_ENC)
#define gmtls_construct_rsa_certs(s,l)	\
	gmtls_output_cert_chain(s,l,SSL_PKEY_RSA_SIGN,SSL_PKEY_RSA_ENC)

static int gmtls_process_sm2_certs(SSL *s, PACKET *pkt, int *al)
{
	return 0;
}

static int gmtls_process_rsa_certs(SSL *s, PACKET *pkt, int *al)
{
	return 0;
}

static int gmtls_construct_sm9_params(SSL *s, unsigned char **p, int *l, int *al, int ibe)
{
	CERT_SM9 *sm9;
	unsigned char *d;
	size_t idlen;
	int n;

	*al = SSL_AD_INTERNAL_ERROR;
	sm9 = ibe ? &s->cert->ibe : &s->cert->ibs;

	if (!sm9->id || !sm9->params) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SM9_PARAMS, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	idlen = strlen(sm9->id);
	if (!idlen || idlen > SM9_MAX_ID_LENGTH) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SM9_PARAMS, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	d = *p;
	s2n(idlen, d);
	memcpy(d, sm9->id, idlen);
	d += idlen;

	*p = d + 3;
	if ((n = i2d_SM9PublicParameters(sm9->params, p)) < 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SM9_PARAMS, ERR_R_SM9_LIB);
		return 0;
	}
	l2n3(n, d);

	*l = 2 + idlen + 3 + n;
	*al = -1;
	return 1;
}

static int gmtls_process_sm9_params(SSL *s, PACKET *pkt, int *al, int ibe)
{
	CERT_SM9 *sm9;
	PACKET id, params;
	const unsigned char *p;

	*al = SSL_AD_INTERNAL_ERROR;
	sm9 = ibe ? &s->session->ibe : &s->session->ibs;

	if (sm9->id || sm9->params || sm9->publickey) {
		SSLerr(SSL_F_GMTLS_PROCESS_SM9_PARAMS, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	if (!PACKET_get_length_prefixed_2(pkt, &id)) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SM9_PARAMS, SSL_R_LENGTH_MISMATCH);
		return 0;
	}
	if (PACKET_remaining(&id) <= 0
		|| PACKET_remaining(&id) > SM9_MAX_ID_LENGTH
		|| !PACKET_data(&id)[PACKET_remaining(&id) - 1]) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SM9_PARAMS, SSL_R_LENGTH_MISMATCH);
		return 0;
	}
	if (!(sm9->id = OPENSSL_malloc(PACKET_remaining(&id) + 1))) {
		SSLerr(SSL_F_GMTLS_PROCESS_SM9_PARAMS, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	memcpy(sm9->id, PACKET_data(&id), PACKET_remaining(&id));
	sm9->id[PACKET_remaining(&id)] = 0;

	if (!PACKET_get_length_prefixed_3(pkt, &params)) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SM9_PARAMS, SSL_R_LENGTH_MISMATCH);
		return 0;
	}
	p = PACKET_data(&params);
	if (!(sm9->params = d2i_SM9PublicParameters(NULL, &p,
		PACKET_remaining(&params)))) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SM9_PARAMS, ERR_R_INTERNAL_ERROR);// rename this error
		return 0;
	}
	/* check there is no remaining data */
	if (p != PACKET_data(&params) + PACKET_remaining(&params)) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SM9_PARAMS, SSL_R_LENGTH_MISMATCH);
		return 0;
	}

	*al = -1;
	return 1;
}

#define gmtls_construct_ibe_params(s,p,l,al) gmtls_construct_sm9_params(s,p,l,al,1)
#define gmtls_construct_ibs_params(s,p,l,al) gmtls_construct_sm9_params(s,p,l,al,0)
#define gmtls_process_ibe_params(s,pkt,al) gmtls_process_sm9_params(s,pkt,al,1)
#define gmtls_process_ibs_params(s,pkt,al) gmtls_process_sm9_params(s,pkt,al,0)

int gmtls_construct_server_certificate(SSL *s)
{
	unsigned long alg_a;
	alg_a = s->s3->tmp.new_cipher->algorithm_auth;
	int l;
	unsigned char *p;
    int al = -1;

	l = 3 + SSL_HM_HEADER_LENGTH(s);

	if (alg_a & SSL_aSM2) {
		if (!gmtls_construct_sm2_certs(s, &l)) {
			SSLerr(SSL_F_GMTLS_CONSTRUCT_SERVER_CERTIFICATE,
				ERR_R_INTERNAL_ERROR);
			goto err;
		}
	} else if (alg_a & SSL_aRSA) {
		if (!gmtls_construct_rsa_certs(s, &l)) {
			SSLerr(SSL_F_GMTLS_CONSTRUCT_SERVER_CERTIFICATE,
				ERR_R_INTERNAL_ERROR);
			goto err;
		}
	} else if (alg_a & SSL_aSM9) {
		if (!gmtls_construct_ibs_params(s, &p, &l, &al)) {
			SSLerr(SSL_F_GMTLS_CONSTRUCT_SERVER_CERTIFICATE,
				ERR_R_INTERNAL_ERROR);
			goto err;
		}
	} else {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SERVER_CERTIFICATE,
			ERR_R_INTERNAL_ERROR);
		goto err;
	}

	if (!ssl_set_handshake_header(s, SSL3_MT_CERTIFICATE, l)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SERVER_CERTIFICATE,
			ERR_R_INTERNAL_ERROR);
		return 0;
	}

    return 1;

err:
	ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
	ossl_statem_set_error(s);
	return 0;
}

static int gmtls_process_server_certs(SSL *s, PACKET *pkt, int *al)
{
	int ret;
	STACK_OF(X509) *sk;

	if ((ret = tls_process_server_certificate(s, pkt)) !=
		MSG_PROCESS_CONTINUE_READING) {
		SSLerr(SSL_F_GMTLS_PROCESS_SERVER_CERTS,
			ERR_R_INTERNAL_ERROR);
		return ret;
	}
	if (!(sk = s->session->peer_chain)) {
		SSLerr(SSL_F_GMTLS_PROCESS_SERVER_CERTS,
			ERR_R_INTERNAL_ERROR);
		goto err;
	}

	/* check double certs */
	if (sk_X509_num(sk) < 2) {
		SSLerr(SSL_F_GMTLS_PROCESS_SERVER_CERTS,
			SSL_R_INVALID_CERT_CHAIN);
		goto err;
	}
	if (!(X509_get_key_usage(sk_X509_value(sk, 0)) &
		X509v3_KU_DIGITAL_SIGNATURE)) {
		SSLerr(SSL_F_GMTLS_PROCESS_SERVER_CERTS,
			SSL_R_INVALID_CERT_CHAIN);
		goto err;
	}
	if (!(X509_get_key_usage(sk_X509_value(sk, 1)) &
		(X509v3_KU_KEY_ENCIPHERMENT | X509v3_KU_KEY_AGREEMENT))) {
		SSLerr(SSL_F_GMTLS_PROCESS_SERVER_CERTS,
			SSL_R_INVALID_CERT_CHAIN);
		goto err;
	}
err:
	return 0;
}

MSG_PROCESS_RETURN gmtls_process_server_certificate(SSL *s, PACKET *pkt)
{
	int al = -1;
	unsigned long alg_a = s->s3->tmp.new_cipher->algorithm_auth;

	if (alg_a & SSL_aSM2) {
		if (!gmtls_process_sm2_certs(s, pkt, &al)) {
			SSLerr(SSL_F_GMTLS_PROCESS_SERVER_CERTIFICATE,
				ERR_R_INTERNAL_ERROR);
			goto err;
		}
	} else if (alg_a & SSL_aRSA) {
		if (!gmtls_process_rsa_certs(s, pkt, &al)) {
			SSLerr(SSL_F_GMTLS_PROCESS_SERVER_CERTIFICATE,
				ERR_R_INTERNAL_ERROR);
			goto err;
		}
	} else if (alg_a & SSL_aSM9) {
		if (!gmtls_process_ibs_params(s, pkt, &al)) {
			SSLerr(SSL_F_GMTLS_PROCESS_SERVER_CERTIFICATE,
				ERR_R_INTERNAL_ERROR);
			goto err;
		}
	} else {
		al = SSL_AD_INTERNAL_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SERVER_CERTIFICATE, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	return MSG_PROCESS_CONTINUE_READING;

err:
	ssl3_send_alert(s, SSL3_AL_FATAL, al);
	ossl_statem_set_error(s);
	return MSG_PROCESS_ERROR;
}

static int gmtls_construct_ske_sm2dhe(SSL *s, unsigned char **p, int *l, int *al)
{
	int ret = 0;
	X509 *x509;
	EVP_PKEY *pkey;
	unsigned char *d;
	int curve_id;
	unsigned char *encodedPoint = NULL;
	int encodedlen;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char z[EVP_MAX_MD_SIZE];
	size_t zlen;
	char *id = NULL;
	unsigned int siglen;

	*al = SSL_AD_INTERNAL_ERROR;

	/* get signing cert and pkey */
	if (!(x509 = s->cert->pkeys[SSL_PKEY_SM2].x509)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_EVP_LIB);
		return 0;
	}
	if (!(pkey = s->cert->pkeys[SSL_PKEY_SM2].privatekey)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	/* check tmp pkey not set */
	if (s->s3->tmp.pkey) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	d = *p;

	/* output ECParameters as NameCurve */
	*d++ = NAMED_CURVE_TYPE;
	*d++ = 0;
	*d++ = 30;

	/* generate tmp pkey and output ECPoint */
	if (!(curve_id = tls1_ec_nid2curve_id(NID_sm2p256v1))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (!(s->s3->tmp.pkey = ssl_generate_pkey_curve(curve_id))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (!(encodedlen = EVP_PKEY_get1_tls_encodedpoint(s->s3->tmp.pkey,
		&encodedPoint))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	*d++ = encodedlen;
	memcpy(d, encodedPoint, encodedlen);
	d += encodedlen;

	/* malloc sign ctx */
	if (!(md_ctx = EVP_MD_CTX_new())) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* sign digest of {client_random, server_random, sm2dhe_params} */
	if (EVP_SignInit_ex(md_ctx, EVP_sm3(), NULL) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_EVP_LIB);
		goto end;
	}
//	if (!(id = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0))) {
//		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_EVP_LIB);
//		goto end;
//	}
    id = SM2_DEFAULT_ID;
	zlen = sizeof(z);
	if (!SM2_compute_id_digest(EVP_sm3(), id, strlen(id), z, &zlen,
		EVP_PKEY_get0_EC_KEY(pkey))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_SM2_LIB);
		goto end;
	}

	if (EVP_SignUpdate(md_ctx, z, zlen) <= 0
		|| EVP_SignUpdate(md_ctx, &(s->s3->client_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_SignUpdate(md_ctx, &(s->s3->server_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_SignUpdate(md_ctx, *p, 4 + encodedlen) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_EVP_LIB);
		goto end;
	}

	if (EVP_PKEY_size(pkey) < 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		goto end;
	}
	siglen = (unsigned int)EVP_PKEY_size(pkey);
	if (EVP_SignFinal(md_ctx, &(d[2]), &siglen, pkey) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2DHE, ERR_R_EVP_LIB);
		goto end;
	}
        s2n(siglen, d);
	d += siglen;

	*l += d - *p;
	*p = d;
	*al = -1;
	ret = 1;

end:
	if (!ret && s->s3->tmp.pkey) {
		EVP_PKEY_free(s->s3->tmp.pkey);
		s->s3->tmp.pkey = NULL;
	}
	OPENSSL_free(encodedPoint);
	EVP_MD_CTX_free(md_ctx);
	OPENSSL_free(id);
	return ret;
}

static int gmtls_process_ske_sm2dhe(SSL *s, PACKET *pkt, int *al)
{
	int ret = 0;
	const unsigned char *ecparams;
	PACKET encoded_pt;
	EVP_PKEY_CTX *pctx = NULL;
	int paramslen;
	PACKET signature;
	EVP_PKEY *pkey;
	int maxsig;
	char *id = NULL;
	unsigned char z[EVP_MAX_MD_SIZE];
	size_t zlen;
	EVP_MD_CTX *md_ctx = NULL;

	*al = SSL_AD_INTERNAL_ERROR;

	/* parse ECParameter */
	if (!PACKET_get_bytes(pkt, &ecparams, 3)) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, SSL_R_LENGTH_TOO_SHORT);
		return 0;
	}
	if (ecparams[0] != NAMED_CURVE_TYPE || ecparams[1] != 0 || ecparams[2] != 30) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, SSL_R_WRONG_CURVE);
		return 0;
	}

	/* parse ECPoint */
	if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt)) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, SSL_R_LENGTH_MISMATCH);
		return 0;
	}

	if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	if (EVP_PKEY_paramgen_init(pctx) <= 0
		|| EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2p256v1) <= 0
		|| EVP_PKEY_paramgen(pctx, &s->s3->peer_tmp) <= 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, ERR_R_EVP_LIB);
		goto end;
	}
	if (s->s3->peer_tmp) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		goto end;
	}
	if (!EVP_PKEY_set1_tls_encodedpoint(s->s3->peer_tmp,
		PACKET_data(&encoded_pt), PACKET_remaining(&encoded_pt))) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, SSL_R_BAD_ECPOINT);
		goto end;
	}

	// s->s3->peer_tmp need to be free-ed when error happed?


	/* get ECDHEParams length */
	paramslen = PACKET_data(pkt) - ecparams;

	/* parse signature packet, check no data remaining */
	if (!PACKET_get_length_prefixed_2(pkt, &signature)
		|| PACKET_remaining(pkt) != 0) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, SSL_R_LENGTH_MISMATCH);
		goto end;
	}
	if (!(pkey = X509_get0_pubkey(s->session->peer))) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		goto end;
	}
	if ((maxsig = EVP_PKEY_size(pkey)) < 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		goto end;
	}
	if (PACKET_remaining(&signature) > (size_t)maxsig) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, SSL_R_WRONG_SIGNATURE_LENGTH);
		goto end;
	}

	/* prepare sm2 z value */
//	if (!(id = X509_NAME_oneline(
//		X509_get_subject_name(s->session->peer), NULL, 0))) {
//		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, ERR_R_EVP_LIB);
//		goto end;
//	}
    id = SM2_DEFAULT_ID;
	zlen = sizeof(z);
	if (!SM2_compute_id_digest(EVP_sm3(), id, strlen(id), z, &zlen,
		EVP_PKEY_get0_EC_KEY(pkey))) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, ERR_R_SM2_LIB);
		goto end;
	}

	/* verify the signature */
	if (!(md_ctx = EVP_MD_CTX_new())) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (EVP_VerifyInit_ex(md_ctx, EVP_sm3(), NULL) <= 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_VerifyUpdate(md_ctx, z, zlen) <= 0
		|| EVP_VerifyUpdate(md_ctx, &(s->s3->client_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_VerifyUpdate(md_ctx, &(s->s3->server_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_VerifyUpdate(md_ctx, ecparams, paramslen) <= 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_VerifyFinal(md_ctx, PACKET_data(&signature),
		PACKET_remaining(&signature), pkey) <= 0) {
		*al = SSL_AD_DECRYPT_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2DHE, SSL_R_BAD_SIGNATURE);
		goto end;
	}

	*al = -1;
	ret = 1;

end:
	EVP_PKEY_CTX_free(pctx);
	OPENSSL_free(id);
	EVP_MD_CTX_free(md_ctx);
	return ret;
}

static unsigned char *gmtls_new_cert_packet(X509 *x, int *l)
{
	unsigned char *ret = NULL;
	unsigned char *p;
	int n;

	if ((n = i2d_X509(x, NULL)) <= 0) {
		SSLerr(SSL_F_GMTLS_NEW_CERT_PACKET, ERR_R_X509_LIB);
		return NULL;
	}
	if (!(ret = OPENSSL_malloc(n + 3))) {
		SSLerr(SSL_F_GMTLS_NEW_CERT_PACKET, ERR_R_X509_LIB);
		return 0;
	}

	p = &(ret[3]);
	if ((n = i2d_X509(x, &p)) <= 0) {
		SSLerr(SSL_F_GMTLS_NEW_CERT_PACKET, ERR_R_X509_LIB);
		goto end;
	}

	p = ret;
	l2n3(n, p);
	*l = n+3;

end:
	return ret;
}

static int gmtls_construct_ske_sm2(SSL *s, unsigned char **p, int *l, int *al)
{
	int ret = 0;
	EVP_PKEY *pkey;
	X509 *x509;
	unsigned char *buf = NULL;
	int n;
	EVP_MD_CTX *md_ctx = NULL;
	char *id = NULL;
	unsigned char z[EVP_MAX_MD_SIZE];
	size_t zlen;
	unsigned char *d;
	unsigned int siglen;

	*al = SSL_AD_INTERNAL_ERROR;

	/* prepare sign key */
	if (!(pkey = s->cert->pkeys[SSL_PKEY_SM2].privatekey)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* prepare encrypt cert buffer */
	if (!(x509 = s->cert->pkeys[SSL_PKEY_SM2_ENC].x509)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (!(buf = gmtls_new_cert_packet(x509, &n))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* mallco ctx */
	if (!(md_ctx = EVP_MD_CTX_new())) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* sign digest of {client_random, server_random, enc_cert} */
	if (EVP_SignInit_ex(md_ctx, EVP_sm3(), NULL) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2, ERR_R_EVP_LIB);
		goto end;
	}
//	if (!(id = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0))) {
//		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2, ERR_R_EVP_LIB);
//		goto end;
//	}
    id = SM2_DEFAULT_ID;
	zlen = sizeof(z);
	if (!SM2_compute_id_digest(EVP_sm3(), id, strlen(id), z, &zlen,
		EVP_PKEY_get0_EC_KEY(pkey))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2, ERR_R_SM2_LIB);
		goto end;
	}

#ifdef GMTLS_DEBUG
	{
        int i;
        printf("Z=");
        for (i = 0; i< zlen; i++)
            printf("%02X",z[i]);
        printf("\n");

        printf("C=");
        for (i = 0; i < n; i++)
            printf("%02X",buf[i]);
        printf("\n");
    }
#endif

	if (EVP_SignUpdate(md_ctx, z, zlen) <= 0
		|| EVP_SignUpdate(md_ctx, &(s->s3->client_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_SignUpdate(md_ctx, &(s->s3->server_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_SignUpdate(md_ctx, buf, n) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2, ERR_R_EVP_LIB);
		goto end;
	}

	/* generate signature */
	if (EVP_PKEY_size(pkey) < 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2, ERR_R_EVP_LIB);
		goto end;
	}
	d = *p;
	siglen = EVP_PKEY_size(pkey);
	if (EVP_SignFinal(md_ctx, &(d[2]), &siglen, pkey) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM2, ERR_R_EVP_LIB);
		goto end;
	}
        s2n(siglen, d);

	*p += 2 + siglen;
	*l += 2 + siglen;
	*al = -1;
	ret = 1;

end:
	OPENSSL_free(buf);
	EVP_MD_CTX_free(md_ctx);
	// OPENSSL_free(id);
	return ret;
}

static int gmtls_process_ske_sm2(SSL *s, PACKET *pkt, int *al)
{
	int ret = 0;
	EVP_PKEY *pkey;
	X509 *x509;
	unsigned char *buf = NULL;
	int n;
	PACKET signature;
	int maxsig;
	EVP_MD_CTX *md_ctx = NULL;
	char *id = NULL;
	unsigned char z[EVP_MAX_MD_SIZE];
	size_t zlen;

	*al = SSL_AD_INTERNAL_ERROR;

	/* get peer's signing pkey */
	if (!(pkey = X509_get0_pubkey(s->session->peer))) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* get peer's encryption cert */
	if (!(x509 = sk_X509_value(s->session->peer_chain, 1))) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (!(buf = gmtls_new_cert_packet(x509, &n))) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* get signature packet, check no data remaining */
	if (!PACKET_get_length_prefixed_2(pkt, &signature)
		|| PACKET_remaining(pkt) != 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2, SSL_R_LENGTH_MISMATCH);
		goto end;
	}
	maxsig = EVP_PKEY_size(pkey);
	if (maxsig < 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2, ERR_R_INTERNAL_ERROR);
		goto end;
	}
	if (PACKET_remaining(&signature) > (size_t)maxsig) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2, SSL_R_WRONG_SIGNATURE_LENGTH);
		goto end;
	}

	/* verify the signature */
	if (!(md_ctx = EVP_MD_CTX_new())) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_VerifyInit_ex(md_ctx, EVP_sm3(), NULL) <= 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2, ERR_R_EVP_LIB);
		goto end;
	}

	/* prepare sm2 z value */
//	if (!(id = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0))) {
//		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2, ERR_R_EVP_LIB);
//		goto end;
//	}
    id = SM2_DEFAULT_ID;
	zlen = sizeof(z);
	if (!SM2_compute_id_digest(EVP_sm3(), id, strlen(id), z, &zlen,
		EVP_PKEY_get0_EC_KEY(pkey))) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2, ERR_R_SM2_LIB);
		goto end;
	}

	{ int i; printf("Z="); for (i=0;i<zlen;i++) printf("%02X",z[i]); printf("\n"); }
	{ int i; printf("C="); for (i=0;i<n;i++) printf("%02X",buf[i]); printf("\n"); }


	if (EVP_VerifyUpdate(md_ctx, z, zlen) <= 0
		|| EVP_VerifyUpdate(md_ctx, &(s->s3->client_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_VerifyUpdate(md_ctx, &(s->s3->server_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_VerifyUpdate(md_ctx, buf, n) <= 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_VerifyFinal(md_ctx, PACKET_data(&signature),
		PACKET_remaining(&signature), pkey) <= 0) {
		*al = SSL_AD_DECRYPT_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM2, SSL_R_BAD_SIGNATURE);
		ERR_print_errors_fp(stderr);
		goto end;
	}

	*al = -1;
	ret = 1;

end:
	OPENSSL_free(buf);
	EVP_MD_CTX_free(md_ctx);
	// OPENSSL_free(id);
	return ret;
}

static int gmtls_construct_ske_sm9(SSL *s, unsigned char **p, int *l, int *al, int dhe)
{
	int ret = 0;
	unsigned char *d;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	size_t siglen;

	*al = SSL_AD_INTERNAL_ERROR;

	if (!s->cert->ibe.params || !s->cert->ibe.id
		|| !s->cert->ibs.params || !s->cert->ibs.privatekey) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM9, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* output IBE id and public parameters */
	d = *p;
	if (!gmtls_construct_ibe_params(s, p, l, al)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM9, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	if (!(md_ctx = EVP_MD_CTX_new())) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM9, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	/* digest {ibe_params, randoms, ibe_enckey} */
	if (EVP_DigestInit_ex(md_ctx, EVP_sm3(), NULL) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM9, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_DigestUpdate(md_ctx, &(s->s3->client_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_DigestUpdate(md_ctx, &(s->s3->server_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_DigestUpdate(md_ctx, d, *l) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM9, ERR_R_EVP_LIB);
		goto end;
	}
	if (dhe) {
		/* prepare IBE encryption key */
		unsigned char ibc_enckey[1024];
		if (!SM9PrivateKey_get_gmtls_public_key(s->cert->ibe.params,
			s->cert->ibe.privatekey, ibc_enckey)) {
			SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM9, ERR_R_INTERNAL_ERROR);
			goto end;
		}
		if (EVP_DigestUpdate(md_ctx, ibc_enckey, sizeof(ibc_enckey)) <= 0) {
			SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM9, ERR_R_EVP_LIB);
			goto end;
		}
	}
	dgstlen = sizeof(dgst);
	if (EVP_DigestFinal_ex(md_ctx, dgst, &dgstlen) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM9, ERR_R_EVP_LIB);
		goto end;
	}

	/* sign digest and output signature */
	d = *p;
	siglen = SM9_signature_size(s->cert->ibs.params);
#if 0
	if (!SM9_sign(s->cert->ibs.params, dgst, dgstlen, &(d[2]), &siglen,
		s->cert->ibs.privatekey)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_SM9, ERR_R_SM9_LIB);
		goto end;
	}
#endif
	s2n(siglen, d);

	*l += 2 + siglen;
	*p += *l;
	*al = -1;
	ret = 1;

end:
	EVP_MD_CTX_free(md_ctx);
	return ret;
}

static int gmtls_process_ske_sm9(SSL *s, PACKET *pkt, int *al, int dhe)
{
	int ret = 0;
	const unsigned char *d;
	int n;
	PACKET signature;
	int maxsig;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;

	*al = SSL_AD_INTERNAL_ERROR;

	/* parse ibe params */
	d = PACKET_data(pkt);
	n = PACKET_remaining(pkt);
	if (!gmtls_process_ibe_params(s, pkt, al)) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM9, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	n -= PACKET_remaining(pkt);

	/* parse ibs signature */
	if (!PACKET_get_length_prefixed_2(pkt, &signature)
		|| PACKET_remaining(pkt) != 0) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM9, SSL_R_LENGTH_MISMATCH);
		return 0;
	}
	if ((maxsig = SM9_signature_size(s->session->ibs.params)) < 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM9, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (PACKET_remaining(&signature) > (size_t)maxsig) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM9, SSL_R_WRONG_SIGNATURE_LENGTH);
		return 0;
	}

	/* verify the signature */
	if (!(md_ctx = EVP_MD_CTX_new())) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM9, ERR_R_EVP_LIB);
		return 0;
	}
	if (EVP_DigestInit_ex(md_ctx, EVP_sm3(), NULL) <= 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM9, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_VerifyUpdate(md_ctx, &(s->s3->client_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_VerifyUpdate(md_ctx, &(s->s3->server_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_VerifyUpdate(md_ctx, d, n) <= 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM9, ERR_R_EVP_LIB);
		goto end;
	}
	if (!dhe) {
		SM9PublicKey *pk = NULL;
		unsigned char enckey[1024];
		if (!(pk = SM9_extract_public_key(s->session->ibe.params,
			s->session->ibe.id, strlen(s->session->ibe.id)))) {
			SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM9, ERR_R_INTERNAL_ERROR);
			goto end;
		}
		if (!SM9PublicKey_get_gmtls_encoded(s->session->ibe.params,
			s->session->ibe.publickey, enckey)) {
			SM9PublicKey_free(pk);
			SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM9, ERR_R_INTERNAL_ERROR);
			goto end;
		}
		if (EVP_DigestUpdate(md_ctx, enckey, sizeof(enckey)) <= 0) {
			SM9PublicKey_free(pk);
			SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM9, ERR_R_EVP_LIB);
			goto end;
		}
		SM9PublicKey_free(pk);
	}
	if (EVP_DigestFinal_ex(md_ctx, dgst, &dgstlen) <= 0) {
		*al = SSL_AD_INTERNAL_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM9, ERR_R_EVP_LIB);
		goto end;
	}

	/* verify signature */
#if 0
	if (1 != SM9_verify(s->session->ibs.params, dgst, dgstlen,
		PACKET_data(&signature), PACKET_remaining(&signature),
		s->session->ibs.id, strlen(s->session->ibs.id))) {
		*al = SSL_AD_DECRYPT_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_SM9, SSL_R_BAD_SIGNATURE);
		goto end;
	}
#endif

	ret = 1;

end:
	EVP_MD_CTX_free(md_ctx);
	return ret;
}

static int gmtls_construct_ske_rsa(SSL *s, unsigned char **p, int *l, int *al)
{
	int ret = 0;
	EVP_PKEY *pkey;
	X509 *x509;
	const EVP_MD *md;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char *buf = NULL;
	unsigned char *d;
	int n;
	unsigned int siglen;

	*al = SSL_AD_INTERNAL_ERROR;

	/* get digest algor */
	if (!ssl_cipher_get_evp(s->session, NULL, &md, NULL, NULL, NULL, 0)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_RSA, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* get sign pkey */
	if (!(pkey = s->cert->pkeys[SSL_PKEY_RSA_SIGN].privatekey)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_RSA, ERR_R_INTERNAL_ERROR);
		goto end;
	}

	/* create encryption cert packet */
	if (!(x509 = s->cert->pkeys[SSL_PKEY_SM2_ENC].x509)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_RSA, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (!(buf = gmtls_new_cert_packet(x509, &n))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_RSA, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* generate signature */
	if (!(md_ctx = EVP_MD_CTX_new())) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_RSA, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (EVP_SignInit_ex(md_ctx, md, NULL) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_RSA, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_SignUpdate(md_ctx, &(s->s3->client_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_SignUpdate(md_ctx, &(s->s3->server_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_SignUpdate(md_ctx, buf, n) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_RSA, ERR_R_EVP_LIB);
		goto end;
	}
	siglen = EVP_PKEY_size(pkey);
	d = *p;
	if (EVP_SignFinal(md_ctx, &(d[2]), &siglen, pkey) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SKE_RSA, ERR_R_EVP_LIB);
		goto end;
	}
        s2n(siglen, d);

	*l = 2 + siglen;
	*p += *l;

	*al = -1;
	ret = 1;

end:
	EVP_MD_CTX_free(md_ctx);
	OPENSSL_free(buf);
	return ret;
}

static int gmtls_process_ske_rsa(SSL *s, PACKET *pkt, int *al)
{
	int ret = 0;
	EVP_PKEY *pkey;
	X509 *x509;
	PACKET signature;
	int maxsig;
	unsigned char *buf = NULL;
	int n;
	const EVP_MD *md;
	EVP_MD_CTX *md_ctx = NULL;

	*al = SSL_AD_INTERNAL_ERROR;

	/* get peer's signing pkey */
	if (!(pkey = X509_get0_pubkey(s->session->peer))) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_RSA, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* get peer's encryption cert */
	if (!(x509 = sk_X509_value(s->session->peer_chain, 1))) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_RSA, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* get signature packet, check no data remaining */
	if (!PACKET_get_length_prefixed_2(pkt, &signature) ||
		PACKET_remaining(pkt) != 0) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_RSA, SSL_R_LENGTH_MISMATCH);
		return 0;
	}
	maxsig = EVP_PKEY_size(pkey);
	if (maxsig < 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_RSA, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (PACKET_remaining(&signature) > (size_t)maxsig) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_RSA, SSL_R_WRONG_SIGNATURE_LENGTH);
		return 0;
	}

	/* encode cert to opaque<1..2^24-1> */
	if (!(buf = gmtls_new_cert_packet(x509, &n))) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_RSA, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* verify the signature */
	if (!(md_ctx = EVP_MD_CTX_new())) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_RSA, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_VerifyInit_ex(md_ctx, md, NULL) <= 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_RSA, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_VerifyUpdate(md_ctx, &(s->s3->client_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_VerifyUpdate(md_ctx, &(s->s3->server_random[0]),
			SSL3_RANDOM_SIZE) <= 0
		|| EVP_VerifyUpdate(md_ctx, buf, n) <= 0) {
		EVP_MD_CTX_free(md_ctx);
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_RSA, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_VerifyFinal(md_ctx, PACKET_data(&signature),
		PACKET_remaining(&signature), pkey) <= 0) {
		*al = SSL_AD_DECRYPT_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_SKE_RSA, SSL_R_BAD_SIGNATURE);
		goto end;
	}

	*al = -1;
	ret = 1;

end:
	OPENSSL_free(buf);
	EVP_MD_CTX_free(md_ctx);
	return ret;
}

int gmtls_construct_server_key_exchange(SSL *s)
{
	int al = -1;
	unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
	unsigned char *p = ssl_handshake_start(s);
	int l = 0;

	if (alg_k & SSL_kSM2) {
		if (!gmtls_construct_ske_sm2(s, &p, &l, &al)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM2DHE) {
		if (!gmtls_construct_ske_sm2dhe(s, &p, &l, &al)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM9) {
		if (!gmtls_construct_ske_sm9(s, &p, &l, &al, 0)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM9DHE) {
		if (!gmtls_construct_ske_sm9(s, &p, &l, &al, 1)) {
			goto err;
		}
	} else if (alg_k & SSL_kRSA) {
		if (!gmtls_construct_ske_rsa(s, &p, &l, &al)) {
			goto err;
		}
	} else {
		al = SSL_AD_HANDSHAKE_FAILURE;
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
			ERR_R_INTERNAL_ERROR);
		goto err;
	}

	if (!ssl_set_handshake_header(s, SSL3_MT_SERVER_KEY_EXCHANGE, l)) {
		al = SSL_AD_HANDSHAKE_FAILURE;
		SSLerr(SSL_F_GMTLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
			ERR_R_INTERNAL_ERROR);
		goto err;
	}

	return 1;

err:
	ssl3_send_alert(s, SSL3_AL_FATAL, al);
	ossl_statem_set_error(s);
	return 0;
}

MSG_PROCESS_RETURN gmtls_process_server_key_exchange(SSL *s, PACKET *pkt)
{
	int al = -1;
	unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

	if (alg_k & SSL_kSM2DHE) {
		if (!gmtls_process_ske_sm2dhe(s, pkt, &al)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM2) {
		if (!gmtls_process_ske_sm2(s, pkt, &al)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM9DHE) {
		if (!gmtls_process_ske_sm9(s, pkt, &al, 1)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM9) {
		if (!gmtls_process_ske_sm9(s, pkt, &al, 0)) {
			goto err;
		}
	} else if (alg_k & SSL_kRSA) {
		if (!gmtls_process_ske_rsa(s, pkt, &al)) {
			goto err;
		}
	} else {
	}

	return MSG_PROCESS_CONTINUE_READING;

err:
	if (al != -1)
		ssl3_send_alert(s, SSL3_AL_FATAL, al);
	ossl_statem_set_error(s);
	return MSG_PROCESS_ERROR;
}

int gmtls_construct_client_certificate(SSL *s)
{
	int al = -1;
	unsigned long alg_a = s->s3->tmp.new_cipher->algorithm_auth;
	unsigned char *p;
	int l = 3 + SSL_HM_HEADER_LENGTH(s);

	if (alg_a & SSL_aSM2) {
		if (!gmtls_construct_sm2_certs(s, &l)) {
			SSLerr(SSL_F_GMTLS_CONSTRUCT_CLIENT_CERTIFICATE,
				ERR_R_INTERNAL_ERROR);
			goto err;
		}
	} else if (alg_a & SSL_aRSA) {
		if (!gmtls_construct_rsa_certs(s, &l)) {
			SSLerr(SSL_F_GMTLS_CONSTRUCT_CLIENT_CERTIFICATE,
				ERR_R_INTERNAL_ERROR);
			goto err;
		}
	} else if (alg_a & SSL_aSM9) {
		if (!gmtls_construct_ibs_params(s, &p, &l, &al)) {
			SSLerr(SSL_F_GMTLS_CONSTRUCT_CLIENT_CERTIFICATE,
				ERR_R_INTERNAL_ERROR);
			goto err;
		}
	}  else {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CLIENT_CERTIFICATE,
			ERR_R_INTERNAL_ERROR);
		goto err;
	}

	if (!ssl_set_handshake_header(s, SSL3_MT_CERTIFICATE, l)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CLIENT_CERTIFICATE,
			ERR_R_INTERNAL_ERROR);
		return 0;
	}

	return 1;

err:
	ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
	ossl_statem_set_error(s);
	return 0;
}

MSG_PROCESS_RETURN gmtls_process_client_certificate(SSL *s, PACKET *pkt)
{

	int ret = MSG_PROCESS_ERROR;
	ret = tls_process_client_certificate(s, pkt);
	return ret;
}

static int gmtls_sm2_derive(SSL *s, EVP_PKEY *privkey, EVP_PKEY *pubkey, int initiator)
{
	int ret = 0;
	EC_KEY *peer_ephem;
	EC_KEY *ephem;
	X509 *x509;
	EVP_PKEY *pkey;
	EC_KEY *sk;
	X509 *peer_x509;
	EVP_PKEY *peer_pkey;
	EC_KEY *peer_pk;
	char *id = NULL;
	unsigned char z[EVP_MAX_MD_SIZE];
	size_t zlen;
	char *peer_id = NULL;
	unsigned char peer_z[EVP_MAX_MD_SIZE];
	size_t peer_zlen;
	unsigned char *pms = NULL;
	size_t pmslen;

	if (!(peer_ephem = EVP_PKEY_get0_EC_KEY(pubkey))) {
		SSLerr(SSL_F_GMTLS_SM2_DERIVE, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (!(ephem = EVP_PKEY_get0_EC_KEY(privkey))) {
		SSLerr(SSL_F_GMTLS_SM2_DERIVE, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* prepare long-term keys */
	if (!(x509 = s->cert->pkeys[SSL_PKEY_SM2_ENC].x509)) {
		SSLerr(SSL_F_GMTLS_SM2_DERIVE, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (!(pkey = s->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey)) {
		SSLerr(SSL_F_GMTLS_SM2_DERIVE, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (!(sk = EVP_PKEY_get0_EC_KEY(pkey))) {
		SSLerr(SSL_F_GMTLS_SM2_DERIVE, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	if (!(peer_x509 = sk_X509_value(s->session->peer_chain, 1))) {
		SSLerr(SSL_F_GMTLS_SM2_DERIVE, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	peer_pkey = X509_get0_pubkey(x509);
	if (!(peer_pk = EVP_PKEY_get0_EC_KEY(pkey))) {
		SSLerr(SSL_F_GMTLS_SM2_DERIVE, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* generate z values */
	if (!(id = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0))) {
		SSLerr(SSL_F_GMTLS_SM2_DERIVE, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (!SM2_compute_id_digest(EVP_sm3(), id, strlen(id), z, &zlen, sk)) {
		SSLerr(SSL_F_GMTLS_SM2_DERIVE, ERR_R_INTERNAL_ERROR);
		goto end;
	}

	if (!(peer_id = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0))) {
		SSLerr(SSL_F_GMTLS_SM2_DERIVE, ERR_R_INTERNAL_ERROR);
		goto end;
	}
	if (!SM2_compute_id_digest(EVP_sm3(), peer_id, strlen(peer_id),
		peer_z, &peer_zlen, peer_pk)) {
		SSLerr(SSL_F_GMTLS_SM2_DERIVE, ERR_R_INTERNAL_ERROR);
		goto end;
	}

	// how to set pmslen ??
	pmslen = 48;

	/* sm2 key exchange */
	if (!SM2_compute_share_key(pms, &pmslen,
		EC_KEY_get0_public_key(peer_ephem), ephem,
		EC_KEY_get0_public_key(peer_pk), peer_z, sizeof(peer_z),
		z, sizeof(z), sk, initiator)) {
		SSLerr(SSL_F_GMTLS_SM2_DERIVE, ERR_R_INTERNAL_ERROR);
		goto end;
	}

	if (s->server) {
		ret = ssl_generate_master_secret(s, pms, pmslen, 1);
		pms = NULL;
	} else {
		s->s3->tmp.pms = pms;
		s->s3->tmp.pmslen = pmslen;
		pms = NULL;
		ret = 1;
	}

end:
	OPENSSL_free(id);
	OPENSSL_free(peer_id);
	return ret;
}

static int gmtls_construct_cke_sm2dhe(SSL *s, unsigned char **p, int *l, int *al)
{
	int ret = 0;
	EVP_PKEY *skey;
	unsigned char *d;
	EVP_PKEY *ckey = NULL;
	unsigned char *encodedPoint = NULL;
	int encodedlen;

	*al = SSL_AD_INTERNAL_ERROR;

	if (!(skey = s->s3->peer_tmp)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	d = *p;
	*d++ = NAMED_CURVE_TYPE;
	*d++ = 0;
	*d++ = 30;

	if (!(ckey = ssl_generate_pkey(skey))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	if (!gmtls_sm2_derive(s, ckey, skey, 0)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		goto end;
	}

	if (!(encodedlen = EVP_PKEY_get1_tls_encodedpoint(ckey, &encodedPoint))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2DHE, ERR_R_EVP_LIB);
		goto end;
	}
	*d++ = encodedlen;
	memcpy(d, encodedPoint, encodedlen);
	d += encodedlen;

	*l = 4 + encodedlen;
	*p = d;
	*al = -1;
	ret = 1;

end:
	EVP_PKEY_free(ckey);
	OPENSSL_free(encodedPoint);
	return ret;
}

static int gmtls_process_cke_sm2dhe(SSL *s, PACKET *pkt, int *al)
{
	int ret = 0;
	const unsigned char *ecparams;
	PACKET encoded_pt;
	EVP_PKEY *skey = s->s3->tmp.pkey;
	EVP_PKEY *ckey = NULL;

	*al = SSL_AD_INTERNAL_ERROR;

	if (!(skey = s->s3->tmp.pkey)) {
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	if (!PACKET_get_bytes(pkt, &ecparams, 3)) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2DHE, SSL_R_LENGTH_TOO_SHORT);
		return 0;
	}
	if (ecparams[0] != NAMED_CURVE_TYPE || ecparams[1] != 0 || ecparams[2] != 30) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2DHE, SSL_R_WRONG_CURVE);
		return 0;
	}

	/* parse ECPoint */
	if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt)
		|| PACKET_remaining(pkt) != 0) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2DHE, SSL_R_LENGTH_MISMATCH);
		return 0;
	}

	if (!(ckey = EVP_PKEY_new())) {
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2DHE, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	if (EVP_PKEY_copy_parameters(ckey, skey) <= 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2DHE, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_PKEY_set1_tls_encodedpoint(ckey, PACKET_data(&encoded_pt),
		PACKET_remaining(&encoded_pt))) {
		*al = SSL_AD_HANDSHAKE_FAILURE;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2DHE, ERR_R_EVP_LIB);
		goto end;
	}

	if (!gmtls_sm2_derive(s, skey, ckey, 1)) {
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2DHE, ERR_R_INTERNAL_ERROR);
		goto end;
	}

	*al = -1;
	ret = 1;
end:

	EVP_PKEY_free(s->s3->tmp.pkey);
	s->s3->tmp.pkey = NULL;
	EVP_PKEY_free(ckey);
	return ret;
}

static int gmtls_construct_cke_sm2(SSL *s, unsigned char **p, int *l, int *al)
{
	int ret = 0;
	unsigned char *d;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	size_t enclen;
	unsigned char *pms = NULL;
	size_t pmslen = 0;
	X509 *x509;

	*al = SSL_AD_INTERNAL_ERROR;

	/* get sm2 encryption key from enc cert */
	if (!(s->session->peer_chain)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (!(x509 = sk_X509_value(s->session->peer_chain, 1))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	pkey = X509_get0_pubkey(x509);
	if (!EVP_PKEY_get0_EC_KEY(pkey)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* generate pre_master_secret */
	pmslen = SSL_MAX_MASTER_KEY_LENGTH;
	if (!(pms = OPENSSL_malloc(pmslen))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	pms[0] = s->client_version >> 8;
	pms[1] = s->client_version & 0xff;
	if (RAND_bytes(pms + 2, pmslen - 2) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2, ERR_R_INTERNAL_ERROR);
		goto end;
	}

	/* encrypt pre_master_secret */
	if (!(pctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (EVP_PKEY_encrypt_init(pctx) <= 0
		|| !EVP_PKEY_CTX_set_ec_scheme(pctx, NID_sm_scheme)
		|| !EVP_PKEY_CTX_set_ec_encrypt_param(pctx, NID_sm3)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_PKEY_encrypt(pctx, NULL, &enclen, pms, pmslen) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2, ERR_R_EVP_LIB);
		goto end;
	}

	d = *p;
	if (EVP_PKEY_encrypt(pctx, &(d[2]), &enclen, pms, pmslen) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2, SSL_R_BAD_SM2_ENCRYPT);
		goto end;
	}
	s2n(enclen, d);
	d += enclen;

	/* save pre_master_secret */
	if (s->s3->tmp.pms) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM2, ERR_R_INTERNAL_ERROR);
		goto end;
	}
	s->s3->tmp.pms = pms;
	s->s3->tmp.pmslen = pmslen;
	pms = NULL;

	*p = d;
	*l = 2 + enclen;
	*al = -1;
	ret = 1;
end:
	OPENSSL_clear_free(pms, pmslen);
	EVP_PKEY_CTX_free(pctx);
	return ret;
}

static int gmtls_process_cke_sm2(SSL *s, PACKET *pkt, int *al)
{
	int ret = 0;
	EVP_PKEY *pkey;
	PACKET enced_pms;
	unsigned char rand_pms[SSL_MAX_MASTER_KEY_LENGTH];
	EVP_PKEY_CTX *pctx = NULL;
	size_t pmslen;
	unsigned char pms[SSL_MAX_MASTER_KEY_LENGTH];
	int ver_good;
	int i;

	*al = SSL_AD_INTERNAL_ERROR;

	/* prepare decryption key */
	if (!(pkey = s->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey)) {
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2, SSL_R_MISSING_SM2_ENC_CERTIFICATE);
		return 0;
	}

	/* parse encrypted pre_master_secret */
	if (!PACKET_get_length_prefixed_2(pkt, &enced_pms)
		|| PACKET_remaining(pkt) != 0) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2, SSL_R_LENGTH_MISMATCH);
		return 0;
	}

	if (RAND_bytes(rand_pms, sizeof(rand_pms)) <= 0) {
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* decrypt encrypted pre_master_secret */
	if (!(pctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	if (!EVP_PKEY_decrypt_init(pctx)
		|| !EVP_PKEY_CTX_set_ec_scheme(pctx, NID_sm_scheme)
		|| !EVP_PKEY_CTX_set_ec_encrypt_param(pctx, NID_sm3)) {
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2, ERR_R_EVP_LIB);
		goto end;
	}
	pmslen = sizeof(pms);
	if (!EVP_PKEY_decrypt(pctx, pms, &pmslen,
		PACKET_data(&enced_pms), PACKET_remaining(&enced_pms))) {
		*al = SSL_AD_DECRYPT_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2, SSL_R_DECRYPTION_FAILED);
		goto end;
	}

	if (pmslen != SSL_MAX_MASTER_KEY_LENGTH) {
		*al = SSL_AD_DECRYPT_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2, SSL_R_DECRYPTION_FAILED);
		goto end;
	}

	ver_good = constant_time_eq_8(pms[0], (unsigned)(s->client_version >> 8)) &
		constant_time_eq_8(pms[1], (unsigned)(s->client_version & 0xff));

	for (i = 0; i < sizeof(rand_pms); i++) {
		pms[i] = constant_time_select_8(ver_good, pms[i], rand_pms[i]);
	}

	/* generate master_secret */
	if (!ssl_generate_master_secret(s, pms, pmslen, 0)) {
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM2, ERR_R_INTERNAL_ERROR);
		goto end;
	}

	*al = -1;
	ret = 1;

end:
	EVP_PKEY_CTX_free(pctx);
	OPENSSL_cleanse(pms, sizeof(pms));
	return ret;
}

static int gmtls_construct_cke_sm9(SSL *s, unsigned char **p, int *l, int *al)
{
	int ret = 0;
	CERT_SM9 *sm9;
	unsigned char *pms = NULL;
	size_t pmslen;
	size_t enclen;
	unsigned char *d;

	*al = SSL_AD_INTERNAL_ERROR;

	/* malloc and generate pre_master_secret */
	pmslen = SSL_MAX_MASTER_KEY_LENGTH;
	if (!(pms = OPENSSL_malloc(pmslen))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM9, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	pms[0] = s->client_version >> 8;
	pms[1] = s->client_version & 0xff;
	if (RAND_bytes(pms + 2, pmslen - 2) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM9, SSL_R_RANDOM_GENERATOR_ERROR);
		goto end;
	}

	/* encrypt pre_master_secret */
	if (!(sm9 = &s->session->ibe)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM9, ERR_R_INTERNAL_ERROR);
		goto end;
	}


#if 0
	if (!SM9_encrypt(sm9->params, &encparam, pms, pmslen,
		NULL, &enclen, sm9->id, strlen(sm9->id))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM9, ERR_R_INTERNAL_ERROR);
		goto end;
	}
	d = *p;
	if (!SM9_encrypt(sm9->params, &encparam, pms, pmslen,
		&(d[2]), &enclen, sm9->id, strlen(sm9->id))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM9, ERR_R_INTERNAL_ERROR);
		goto end;
	}
#endif

	/* save pre_master_secret */
	s->s3->tmp.pms = pms;
	s->s3->tmp.pmslen = pmslen;
	pms = NULL;

	/* output 2-byte length */
	s2n(enclen, d);
	*p = d + enclen;
	*l = 2 + enclen;
	*al = -1;
	ret = 1;

end:
	OPENSSL_clear_free(pms, pmslen);
	return ret;
}

static int gmtls_process_cke_sm9(SSL *s, PACKET *pkt, int *al)
{
	int ret = 0;
	PACKET enced_pms;
	CERT_SM9 *sm9;
	unsigned char *pms = NULL;
	size_t pms_len;


	*al = SSL_AD_INTERNAL_ERROR;

	if (!PACKET_get_length_prefixed_2(pkt, &enced_pms)
		|| PACKET_remaining(pkt) != 0) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM9, SSL_R_LENGTH_MISMATCH);
		return 0;
	}

	if (!(sm9 = &s->cert->ibe)) {
		*al = SSL_AD_HANDSHAKE_FAILURE;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM9, ERR_R_INTERNAL_ERROR);
		return 0;
	}


#if 0
	if (!SM9_decrypt(sm9->params, &encparam,
		PACKET_data(&enced_pms), PACKET_remaining(&enced_pms), pms, &pms_len,
		sm9->privatekey, sm9->id, strlen(sm9->id))) {
		*al = SSL_AD_DECRYPT_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM9, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	if (pms_len != SSL_MAX_MASTER_KEY_LENGTH) {
		*al = SSL_AD_DECRYPT_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM9, SSL_R_DECRYPTION_FAILED);
		goto end;
	}
#endif

	/* generate master_secret */
	if (!ssl_generate_master_secret(s, pms, pms_len, 0)) {
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM9, ERR_R_INTERNAL_ERROR);
		goto end;
	}

	ret = 1;

end:
	return ret;
}

static int gmtls_construct_cke_sm9dhe(SSL *s, unsigned char **p, int *len, int *al)
{


	*al = SSL_AD_INTERNAL_ERROR;
	SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_SM9DHE, SSL_R_NOT_IMPLEMENTED);
	return 0;
}

static int gmtls_process_cke_sm9dhe(SSL *s, PACKET *pkt, int *al)
{

	*al = SSL_AD_INTERNAL_ERROR;
	SSLerr(SSL_F_GMTLS_PROCESS_CKE_SM9DHE, SSL_R_NOT_IMPLEMENTED);
	return 0;
}

int gmtls_construct_cke_rsa(SSL *s, unsigned char **p, int *len, int *al)
{
#ifndef OPENSSL_NO_RSA
	int ret = 0;
	unsigned char *q;
	X509 *x509;
	EVP_PKEY *pkey;
	EVP_PKEY_CTX *pctx = NULL;
	size_t enclen;
	unsigned char *pms = NULL;
	size_t pmslen = 0;

	/* get peer's encryption cert */
	if (!s->session->peer_chain) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_RSA, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	if (!(x509 = sk_X509_value(s->session->peer_chain, 0))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_RSA, ERR_R_INTERNAL_ERROR);
		return 0;
	}
	pkey = X509_get0_pubkey(x509);
	if (!EVP_PKEY_get0_RSA(pkey)) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_RSA, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* generate pre_master_secret */
	pmslen = SSL_MAX_MASTER_KEY_LENGTH;
	if (!(pms = OPENSSL_malloc(pmslen))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_RSA, ERR_R_MALLOC_FAILURE);
		*al = SSL_AD_INTERNAL_ERROR;
		return 0;
	}
	pms[0] = s->client_version >> 8;
	pms[1] = s->client_version & 0xff;
	if (RAND_bytes(pms + 2, pmslen - 2) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_RSA, ERR_R_INTERNAL_ERROR);
		goto end;
	}
	q = *p;
	*p += 2;

	/* encrypt pre_master_secret and output packet */
	if (!(pctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_RSA, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (EVP_PKEY_encrypt_init(pctx) <= 0
		|| EVP_PKEY_encrypt(pctx, NULL, &enclen, pms, pmslen) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_RSA, ERR_R_EVP_LIB);
		goto end;
	}
	if (EVP_PKEY_encrypt(pctx, *p, &enclen, pms, pmslen) <= 0) {
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_RSA, SSL_R_BAD_RSA_ENCRYPT);
		goto end;
	}
	*len = enclen;

	s2n(*len, q);
	*len += 2;

	/* save local pre_master_secret */
	s->s3->tmp.pms = pms;
	s->s3->tmp.pmslen = pmslen;
	pms = NULL;
	pmslen = 0;

	ret = 1;

end:
	OPENSSL_clear_free(pms, pmslen);
	EVP_PKEY_CTX_free(pctx);
	return ret;
#else
	SSLerr(SSL_F_GMTLS_CONSTRUCT_CKE_RSA, ERR_R_INTERNAL_ERROR);
	*al = SSL_AD_INTERNAL_ERROR;
	return 0;
#endif
}

static int gmtls_process_cke_rsa(SSL *s, PACKET *pkt, int *al)
{
#ifndef OPENSSL_NO_RSA
	unsigned char rand_premaster_secret[SSL_MAX_MASTER_KEY_LENGTH];
	int decrypt_len;
	unsigned char decrypt_good, version_good;
	size_t j, padding_len;
	PACKET enc_premaster;
	RSA *rsa = NULL;
	unsigned char *rsa_decrypt = NULL;
	int ret = 0;

	rsa = EVP_PKEY_get0_RSA(s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey);
	if (rsa == NULL) {
		*al = SSL_AD_HANDSHAKE_FAILURE;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_RSA, SSL_R_MISSING_RSA_CERTIFICATE);
		return 0;
	}

	if (!PACKET_get_length_prefixed_2(pkt, &enc_premaster)
		|| PACKET_remaining(pkt) != 0) {
		*al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_RSA, SSL_R_LENGTH_MISMATCH);
		return 0;
	}

	/*
	* We want to be sure that the plaintext buffer size makes it safe to
	* iterate over the entire size of a premaster secret
	* (SSL_MAX_MASTER_KEY_LENGTH). Reject overly short RSA keys because
	* their ciphertext cannot accommodate a premaster secret anyway.
	*/
	if (RSA_size(rsa) < SSL_MAX_MASTER_KEY_LENGTH) {
		*al = SSL_AD_INTERNAL_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_RSA, RSA_R_KEY_SIZE_TOO_SMALL);
		return 0;
	}

	rsa_decrypt = OPENSSL_malloc(RSA_size(rsa));
	if (rsa_decrypt == NULL) {
		*al = SSL_AD_INTERNAL_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_RSA, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	/*
	* We must not leak whether a decryption failure occurs because of
	* Bleichenbacher's attack on PKCS #1 v1.5 RSA padding (see RFC 2246,
	* section 7.4.7.1). The code follows that advice of the TLS RFC and
	* generates a random premaster secret for the case that the decrypt
	* fails. See https://tools.ietf.org/html/rfc5246#section-7.4.7.1
	*/

	if (RAND_bytes(rand_premaster_secret, sizeof(rand_premaster_secret)) <= 0)
		goto err;

	/*
	* Decrypt with no padding. PKCS#1 padding will be removed as part of
	* the timing-sensitive code below.
	*/
	decrypt_len = RSA_private_decrypt(PACKET_remaining(&enc_premaster),
		PACKET_data(&enc_premaster),
		rsa_decrypt, rsa, RSA_NO_PADDING);
	if (decrypt_len < 0)
		goto err;

	/* Check the padding. See RFC 3447, section 7.2.2. */

	/*
	* The smallest padded premaster is 11 bytes of overhead. Small keys
	* are publicly invalid, so this may return immediately. This ensures
	* PS is at least 8 bytes.
	*/
	if (decrypt_len < 11 + SSL_MAX_MASTER_KEY_LENGTH) {
		*al = SSL_AD_DECRYPT_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_RSA, SSL_R_DECRYPTION_FAILED);
		goto err;
	}

	padding_len = decrypt_len - SSL_MAX_MASTER_KEY_LENGTH;
	decrypt_good = constant_time_eq_int_8(rsa_decrypt[0], 0) &
	constant_time_eq_int_8(rsa_decrypt[1], 2);
	for (j = 2; j < padding_len - 1; j++) {
		decrypt_good &= ~constant_time_is_zero_8(rsa_decrypt[j]);
	}
	decrypt_good &= constant_time_is_zero_8(rsa_decrypt[padding_len - 1]);

	/*
	* If the version in the decrypted pre-master secret is correct then
	* version_good will be 0xff, otherwise it'll be zero. The
	* Klima-Pokorny-Rosa extension of Bleichenbacher's attack
	* (http://eprint.iacr.org/2003/052/) exploits the version number
	* check as a "bad version oracle". Thus version checks are done in
	* constant time and are treated like any other decryption error.
	*/
	version_good =
		constant_time_eq_8(rsa_decrypt[padding_len],
			(unsigned)(s->client_version >> 8));
	version_good &=
		constant_time_eq_8(rsa_decrypt[padding_len + 1],
			(unsigned)(s->client_version & 0xff));

	/*
	* The premaster secret must contain the same version number as the
	* ClientHello to detect version rollback attacks (strangely, the
	* protocol does not offer such protection for DH ciphersuites).
	* However, buggy clients exist that send the negotiated protocol
	* version instead if the server does not support the requested
	* protocol version. If SSL_OP_TLS_ROLLBACK_BUG is set, tolerate such
	* clients.
	*/
	if (s->options & SSL_OP_TLS_ROLLBACK_BUG) {
		unsigned char workaround_good;
		workaround_good = constant_time_eq_8(rsa_decrypt[padding_len],
			(unsigned)(s->version >> 8));
		workaround_good &=
			constant_time_eq_8(rsa_decrypt[padding_len + 1],
				(unsigned)(s->version & 0xff));
		version_good |= workaround_good;
	}

	/*
	* Both decryption and version must be good for decrypt_good to
	* remain non-zero (0xff).
	*/
	decrypt_good &= version_good;

	/*
	* Now copy rand_premaster_secret over from p using
	* decrypt_good_mask. If decryption failed, then p does not
	* contain valid plaintext, however, a check above guarantees
	* it is still sufficiently large to read from.
	*/
	for (j = 0; j < sizeof(rand_premaster_secret); j++) {
		rsa_decrypt[padding_len + j] = constant_time_select_8(
			decrypt_good, rsa_decrypt[padding_len + j],
			rand_premaster_secret[j]
		);
	}

	if (!ssl_generate_master_secret(s, rsa_decrypt + padding_len,
		sizeof(rand_premaster_secret), 0)) {
		*al = SSL_AD_INTERNAL_ERROR;
		SSLerr(SSL_F_GMTLS_PROCESS_CKE_RSA, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	ret = 1;

err:
	OPENSSL_free(rsa_decrypt);
	return ret;
#else
	/* Should never happen */
	*al = SSL_AD_INTERNAL_ERROR;
	SSLerr(SSL_F_GMTLS_PROCESS_CKE_RSA, ERR_R_INTERNAL_ERROR);
	return 0;
#endif
}

int gmtls_construct_client_key_exchange(SSL *s)
{
	int al = -1;
	unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
	unsigned char *p = ssl_handshake_start(s);
	int l;

	if (alg_k & SSL_kRSA) {
		if (!gmtls_construct_cke_rsa(s, &p, &l, &al)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM2) {
		if (!gmtls_construct_cke_sm2(s, &p, &l, &al)) {
			goto err;
		}
	} else if (alg_k & (SSL_kSM2DHE)) {
		if (!gmtls_construct_cke_sm2dhe(s, &p, &l, &al)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM9) {
		if (!gmtls_construct_cke_sm9(s, &p, &l, &al)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM9DHE) {
		if (!gmtls_construct_cke_sm9dhe(s, &p, &l, &al)) {
			goto err;
		}
	} else {
		ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CLIENT_KEY_EXCHANGE,
			ERR_R_INTERNAL_ERROR);
		goto err;
	}

	if (!ssl_set_handshake_header(s, SSL3_MT_CLIENT_KEY_EXCHANGE, l)) {
		ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
		SSLerr(SSL_F_GMTLS_CONSTRUCT_CLIENT_KEY_EXCHANGE,
			ERR_R_INTERNAL_ERROR);
		goto err;
	}

	return 1;
err:
	if (al != -1)
		ssl3_send_alert(s, SSL3_AL_FATAL, al);
	OPENSSL_clear_free(s->s3->tmp.pms, s->s3->tmp.pmslen);
	s->s3->tmp.pms = NULL;
	ossl_statem_set_error(s);
	return 0;
}

MSG_PROCESS_RETURN gmtls_process_client_key_exchange(SSL *s, PACKET *pkt)
{
	int al = -1;
	unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

	if (alg_k & SSL_kRSA) {
		if (!gmtls_process_cke_rsa(s, pkt, &al)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM2) {
		if (!gmtls_process_cke_sm2(s, pkt, &al)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM2DHE) {
		if (!gmtls_process_cke_sm2dhe(s, pkt, &al)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM9) {
		if (!gmtls_process_cke_sm9(s, pkt, &al)) {
			goto err;
		}
	} else if (alg_k & SSL_kSM9DHE) {
		if (!gmtls_process_cke_sm9dhe(s, pkt, &al)) {
			goto err;
		}
	} else {
		al = SSL_AD_HANDSHAKE_FAILURE;
		SSLerr(SSL_F_GMTLS_PROCESS_CLIENT_KEY_EXCHANGE,
		SSL_R_UNKNOWN_CIPHER_TYPE);
		goto err;
	}

	return MSG_PROCESS_CONTINUE_PROCESSING;

err:
	ssl3_send_alert(s, SSL3_AL_FATAL, al);
	ossl_statem_set_error(s);
	return MSG_PROCESS_ERROR;
}
