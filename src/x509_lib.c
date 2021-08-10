/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
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
