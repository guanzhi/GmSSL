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
