/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License);
 *  you may not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_SCT_H
#define GMSSL_SCT_H


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/digest.h>
#include <gmssl/x509_key.h>


#ifdef __cplusplus
extern "C" {
#endif


/*
Certificate Transparency (RFC 6962) uses TLS-style presentation language for
Signed Certificate Timestamp (SCT) objects. When SCTs are carried in an X.509
or OCSP extension, the extension value is an ASN.1 OCTET STRING whose contents
are the TLS-serialized SignedCertificateTimestampList.

id-ct OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 11129 2 4 }

id-ct-precertificate-scts OBJECT IDENTIFIER ::= { id-ct 2 }

ExtnValue contents ::=
	SignedCertificateTimestampList
*/


enum {
	SCT_version_v1 = 0,
};

enum {
	SCT_signature_type_certificate_timestamp = 0,
	SCT_signature_type_tree_hash = 1,
};

enum {
	SCT_log_entry_type_x509_entry = 0,
	SCT_log_entry_type_precert_entry = 1,
};

#define SCT_LOG_ID_SIZE	32
#define SCT_ISSUER_KEY_HASH_SIZE	32
#define SCT_MAX_SIGNED_DATA_SIZE	65536

/*
struct {
	Version sct_version;
	SignatureType signature_type = certificate_timestamp;
	uint64 timestamp;
	LogEntryType entry_type;
	select(entry_type) {
	case x509_entry: ASN.1Cert;
	case precert_entry: PreCert;
	} signed_entry;
	CtExtensions extensions;
} digitally_signed;

ASN.1Cert ::= opaque <1..2^24-1>;

PreCert ::= struct {
	opaque issuer_key_hash[32];
	TBSCertificate tbs_certificate;
}

TBSCertificate ::= opaque <1..2^24-1>;

CtExtensions ::= opaque <0..2^16-1>;
*/
int sct_signed_data_to_bytes(int version, uint64_t timestamp, int entry_type,
	const uint8_t issuer_key_hash[SCT_ISSUER_KEY_HASH_SIZE],
	const uint8_t *entry, size_t entry_len,
	const uint8_t *exts, size_t extslen,
	uint8_t **out, size_t *outlen);
int sct_signed_data_construct(const uint8_t *sct, size_t sct_len,
	int entry_type, const uint8_t issuer_key_hash[SCT_ISSUER_KEY_HASH_SIZE],
	const uint8_t *entry, size_t entry_len,
	uint8_t **out, size_t *outlen);

/*
DigitallySigned ::= struct {
	uint16 sig_algorithm;
	opaque signature<0..2^16-1>;
}
*/
int signed_certificate_timestamp_signature_to_bytes(
	int sig_alg, const uint8_t *sig, size_t siglen,
	uint8_t **out, size_t *outlen);
int signed_certificate_timestamp_signature_from_bytes(
	int *sig_alg, const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen);
int signed_certificate_timestamp_signature_print(FILE *fp, int fmt, int ind,
	const char *label, const uint8_t *d, size_t dlen);


/*
SignedCertificateTimestamp ::= struct {
	Version sct_version;
	LogID id;
	uint64 timestamp;
	CtExtensions extensions;
	DigitallySigned signature;
}

Version ::= enum { v1(0), (255) }

LogID ::= opaque key_id[32];

CtExtensions ::= opaque <0..2^16-1>;
*/
int signed_certificate_timestamp_to_bytes(int version,
	const uint8_t log_id[SCT_LOG_ID_SIZE], uint64_t timestamp,
	const uint8_t *exts, size_t extslen,
	int sig_alg, const uint8_t *sig, size_t siglen,
	uint8_t **out, size_t *outlen);
int signed_certificate_timestamp_from_bytes(int *version,
	const uint8_t **log_id, uint64_t *timestamp,
	const uint8_t **exts, size_t *extslen,
	int *sig_alg, const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen);
int signed_certificate_timestamp_print(FILE *fp, int fmt, int ind,
	const char *label, const uint8_t *d, size_t dlen);
int signed_certificate_timestamp_verify(const uint8_t *sct, size_t sct_len,
	const uint8_t *signed_data, size_t signed_data_len,
	X509_KEY *key, const DIGEST *digest);


/*
在验证sct_list的时候，我们需要提供一组公钥的信息，包括X509_KEY, Key_hash, URL , description 这三个是最重要的了
*/


typedef struct {
	X509_KEY log_key;
	uint8_t log_id[32];
	const char *log_name;
	const char *log_url;
	const char *log_dns_domain;
} CT_LOG_INFO;

int sct_list_verify(const uint8_t *sct_list, size_t sct_list_len,
	int entry_type, const uint8_t issuer_key_hash[SCT_ISSUER_KEY_HASH_SIZE],
	const uint8_t *entry, size_t entry_len,
	const CT_LOG_INFO *ct_logs, size_t ct_logs_cnt,
	size_t at_least);



#ifdef __cplusplus
}
#endif
#endif
