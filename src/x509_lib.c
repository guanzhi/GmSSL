/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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
 */

/*
应用应该只调用这个文件中实现的接口

*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>



int x509_certificate_set_version(X509_CERTIFICATE *cert, int version)
{
	if (version < X509_version_v1 || version > X509_version_v3) {
		error_print();
		return -1;
	}
	cert->tbs_certificate.version = version;
	return 1;
}

int x509_certificate_set_serial_number(X509_CERTIFICATE *cert, const uint8_t *sn, size_t snlen)
{
	if (!cert || !sn || snlen <= 0 || snlen > 20) {
		error_print();
		return -1;
	}
	memcpy(cert->tbs_certificate.serial_number, sn, snlen);
	cert->tbs_certificate.serial_number_len = snlen;
	return 1;
}

int x509_certificate_set_signature_algor_sm2(X509_CERTIFICATE *cert)
{
	cert->tbs_certificate.signature_algor = OID_sm2sign_with_sm3;
	cert->signature_algor = OID_sm2sign_with_sm3;
	return 1;
}

int x509_certificate_set_issuer(X509_CERTIFICATE *cert, const X509_NAME *name)
{
	memcpy(&cert->tbs_certificate.issuer, name, sizeof(X509_NAME));
	return 1;
}

int x509_certificate_set_subject(X509_CERTIFICATE *cert, const X509_NAME *name)
{
	memcpy(&cert->tbs_certificate.subject, name, sizeof(X509_NAME));
	return 1;
}

int x509_certificate_set_validity(X509_CERTIFICATE *cert, time_t not_before, int days)
{
	if (x509_validity_set_days(&cert->tbs_certificate.validity, not_before, days) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_signature_algor(X509_CERTIFICATE *cert, int oid)
{
	cert->tbs_certificate.signature_algor = oid;
	return 1;
}

int x509_certificate_set_subject_public_key_info_sm2(X509_CERTIFICATE *cert, const SM2_KEY *sm2_key)
{
	X509_PUBLIC_KEY_INFO *pkey_info = &cert->tbs_certificate.subject_public_key_info;
	x509_public_key_info_set_sm2(pkey_info, sm2_key);
	return 1;
}

int x509_certificate_set_issuer_unique_id(X509_CERTIFICATE *cert, const uint8_t *id, size_t idlen)
{
	memcpy(cert->tbs_certificate.issuer_unique_id, id, idlen);
	cert->tbs_certificate.issuer_unique_id_len = idlen;
	return 1;
}

int x509_certificate_set_subject_unique_id(X509_CERTIFICATE *cert, const uint8_t *id, size_t idlen)
{
	memcpy(cert->tbs_certificate.subject_unique_id, id, idlen);
	cert->tbs_certificate.subject_unique_id_len = idlen;
	return 1;
}

int x509_certificate_set_issuer_unique_id_from_public_key_sm2(X509_CERTIFICATE *cert, const SM2_KEY *sm2_key)
{
	uint8_t uniq_id[32];
	sm2_public_key_digest(sm2_key, uniq_id);
	x509_certificate_set_issuer_unique_id(cert, uniq_id, sizeof(uniq_id));
	return 1;
}

int x509_certificate_set_subject_unique_id_from_public_key_sm2(X509_CERTIFICATE *cert, const SM2_KEY *sm2_key)
{
	uint8_t uniq_id[32];
	sm2_public_key_digest(sm2_key, uniq_id);
	x509_certificate_set_subject_unique_id(cert, uniq_id, sizeof(uniq_id));
	return 1;
}


int x509_certificate_sign_sm2(X509_CERTIFICATE *cert, const SM2_KEY *key)
{
	SM2_SIGN_CTX ctx;
	uint8_t buf[1024];
	uint8_t *p = buf;
	size_t len = 0;

	cert->signature_algor = OID_sm2sign_with_sm3;
	x509_tbs_certificate_to_der(&cert->tbs_certificate, &p, &len);
	if (sm2_sign_init(&ctx, key, SM2_DEFAULT_ID) != 1
		|| sm2_sign_update(&ctx, buf, len) != 1
		|| sm2_sign_finish(&ctx, cert->signature, &cert->signature_len) != 1) {
		error_print();
		return -1;
	}

	memset(&ctx, 0, sizeof(ctx));
	return 1;
}

// 这个公钥应该是根据issuer name从签名的CA证书中取得的
int x509_certificate_verify_sm2(const X509_CERTIFICATE *cert, const SM2_KEY *sm2_key)
{
	SM2_SIGN_CTX ctx;
	uint8_t buf[1024];
	uint8_t *p = buf;
	size_t len = 0;

	x509_tbs_certificate_to_der(&cert->tbs_certificate, &p, &len);
	if (sm2_verify_init(&ctx, sm2_key, SM2_DEFAULT_ID) != 1
		|| sm2_verify_update(&ctx, buf, len) != 1
		|| sm2_verify_finish(&ctx, cert->signature, cert->signature_len) != 1) {
		return -1;
	}

	memset(&ctx, 0, sizeof(ctx));
	return 1;
}

int x509_certificate_get_public_key_sm2(const X509_CERTIFICATE *cert, SM2_KEY *sm2_key)
{
	*sm2_key = cert->tbs_certificate.subject_public_key_info.sm2_key;
	return 1;
}


int x509_certificate_verify_by_certificate(const X509_CERTIFICATE *cert, const X509_CERTIFICATE *cacert)
{
	int ret;
	SM2_KEY ca_pubkey;

	if (x509_name_equ(&cert->tbs_certificate.issuer, &cacert->tbs_certificate.subject) != 1) {
		error_print();
		return -1;
	}
	if (x509_certificate_get_public_key(cacert, &ca_pubkey) != 1) {
		error_print();
		return -1;
	}
	if ((ret = x509_certificate_verify(cert, &ca_pubkey)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int x509_certificate_from_pem_by_name(X509_CERTIFICATE *cert, FILE *fp, const X509_NAME *issuer)
{
	int ret;
	for (;;) {
		if ((ret = x509_certificate_from_pem(cert, fp)) != 1) {
			if (ret < 0) error_print();
			return ret;
		}
		if (x509_name_equ(&cert->tbs_certificate.subject, issuer) == 1) {
			return 1;
		}
	}
	return 0;
}
