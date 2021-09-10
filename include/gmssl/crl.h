/*
 * Copyright (c) 2020 - 2021 The GmSSL Project.  All rights reserved.
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


#ifndef GMSSL_CRL_H
#define GMSSL_CRL_H



#ifdef __cplusplus
extern "C" {
#endif


typedef enum X509_CRLReason {
	X509_cr_unspecified = 0,
	X509_cr_keyCompromise,
	X509_cr_cACompromise,
	X509_cr_affiliationChanged,
	X509_cr_superseded,
	X509_cr_cessationOfOperation,
	X509_cr_certificateHold,
	X509_cr_7_not_assigned = 7,
	X509_cr_removeFromCRL,
	X509_cr_privilegeWithdrawn,
	X509_cr_aACompromise,
} CRL_REASON;

typedef struct {
	uint8_t serial_number[20];
	size_t serial_number_len;
	time_t revoke_date;
	CRL_EXTENSIONS crlEntryExtensions;
} CRL_REVOKED_CERT;

typedef struct {
	int version; // OPTIONAL, if present MUST be v2
	int signature_algor;
	X509_NAME issuer;
	time_t this_update;
	time_t next_update;
	uint8_t *revoked_certs;
	size_t revoked_certs_count;
	X509_EXTENSION crl_exts[32];
	size_t crl_exts_count;

	uint8_t buf[1024];
} CRL_TBS_CERT_LIST;

typedef struct {
	X509_TBS_CERT_LIST tbs_cert_list;
	int signature_algor;
	uint8_t signature[128];
	size_t signature_len;
} CRL_CERT_LIST;








#ifdef  __cplusplus
}
#endif
#endif
