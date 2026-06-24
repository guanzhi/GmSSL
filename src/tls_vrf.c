/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/tls.h>


static void tls_cert_verify_set_result(int *verify_result, int result)
{
	if (verify_result) {
		*verify_result = result;
	}
}

static int tls_cert_verify_get_cert_group(const uint8_t *cert, size_t certlen, int *group)
{
	X509_KEY public_key;

	if (!cert || !certlen || !group) {
		error_print();
		return -1;
	}
	if (x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1) {
		error_print();
		return -1;
	}
	if (public_key.algor != OID_ec_public_key) {
		error_print();
		return -1;
	}
	if ((*group = tls_named_curve_from_oid(public_key.algor_param)) == 0) {
		error_print();
		return -1;
	}
	return 1;
}

static int tls12_cipher_suite_match_cert_group(int cipher_suite, int cert_group)
{
	switch (cipher_suite) {
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
		return cert_group == TLS_curve_sm2p256v1;
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm:
		return cert_group == TLS_curve_secp256r1;
	default:
		return 0;
	}
}

static int tls12_signature_scheme_match_cert_group(int sig_alg, int cert_group)
{
	return tls_signature_scheme_group_oid(sig_alg) == tls_named_curve_oid(cert_group);
}

static int tls12_signature_scheme_match_cipher_suite(int sig_alg, int cipher_suite)
{
	switch (sig_alg) {
	case TLS_sig_sm2sig_sm3:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_sm4_cbc_sm3:
		case TLS_cipher_ecdhe_sm4_gcm_sm3:
			return 1;
		}
		break;
	case TLS_sig_ecdsa_secp256r1_sha256:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm:
			return 1;
		}
		break;
	}
	return 0;
}

static int tls12_signature_scheme_from_cipher_suite(int cipher_suite)
{
	switch (cipher_suite) {
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecc_sm4_gcm_sm3:
		return TLS_sig_sm2sig_sm3;
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256:
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm:
		return TLS_sig_ecdsa_secp256r1_sha256;
	default:
		return -1;
	}
}

static int tls_cipher_suite_is_tlcp_ecdhe(int cipher_suite)
{
	switch (cipher_suite) {
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
		return 1;
	default:
		return 0;
	}
}

static int tls_cert_chain_check_name(const uint8_t *cert_chain, size_t cert_chain_len,
	const uint8_t *host_name, size_t host_name_len, int *verify_result)
{
	int ret;
	const uint8_t *cert;
	size_t certlen;

	if (!host_name || !host_name_len) {
		return 1;
	}
	if (x509_certs_get_cert_by_index(cert_chain, cert_chain_len, 0, &cert, &certlen) != 1) {
		error_print();
		tls_cert_verify_set_result(verify_result, X509_verify_err_certificate);
		return -1;
	}
	if ((ret = tls_cert_match_server_name(cert, certlen, host_name, host_name_len)) < 0) {
		error_print();
		tls_cert_verify_set_result(verify_result, X509_verify_err_hostname);
		return -1;
	}
	if (ret == 0) {
		error_print();
		tls_cert_verify_set_result(verify_result, X509_verify_err_hostname);
		return 0;
	}
	return 1;
}

static int tls12_cert_chain_match(
	int cert_chain_type, int cipher_suite,
	const uint8_t *cert_chain, size_t cert_chain_len,
	const int *supported_groups, size_t supported_groups_cnt,
	const int *signature_algorithms, size_t signature_algorithms_cnt,
	const int *signature_algorithms_cert, size_t signature_algorithms_cert_cnt,
	const uint8_t *ca_names, size_t ca_names_len,
	const uint8_t *host_name, size_t host_name_len,
	int *verify_result, int *selected_sig_alg)
{
	int ret;
	const uint8_t *cert;
	size_t certlen;
	int cert_group;
	int sig_alg;

	if (x509_certs_get_cert_by_index(cert_chain, cert_chain_len, 0, &cert, &certlen) != 1) {
		error_print();
		tls_cert_verify_set_result(verify_result, X509_verify_err_certificate);
		return -1;
	}

	if (cert_chain_type == X509_cert_chain_server) {
		if (tls_cert_verify_get_cert_group(cert, certlen, &cert_group) != 1) {
			error_print();
			tls_cert_verify_set_result(verify_result, X509_verify_err_certificate);
			return -1;
		}
		if (!tls12_cipher_suite_match_cert_group(cipher_suite, cert_group)) {
			error_print();
			tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
			return 0;
		}
		if (supported_groups && supported_groups_cnt) {
			if (!tls_type_is_in_list(cert_group, supported_groups, supported_groups_cnt)) {
				error_print();
				tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
				return 0;
			}
		}
		sig_alg = tls12_signature_scheme_from_cipher_suite(cipher_suite);
		if (sig_alg < 0) {
			error_print();
			tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
			return -1;
		}
		if (selected_sig_alg) {
			*selected_sig_alg = sig_alg;
		}
	}

	if (signature_algorithms && signature_algorithms_cnt) {
		if ((ret = tls_cert_match_signature_algorithms(cert, certlen,
			signature_algorithms, signature_algorithms_cnt, &sig_alg)) < 0) {
			error_print();
			tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
			return -1;
		}
		if (ret == 0) {
			error_print();
			tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
			return 0;
		}
		if (cert_chain_type == X509_cert_chain_server) {
			if (!tls12_signature_scheme_match_cert_group(sig_alg, cert_group)
				|| !tls12_signature_scheme_match_cipher_suite(sig_alg, cipher_suite)) {
				error_print();
				tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
				return 0;
			}
		}
		if (selected_sig_alg) {
			*selected_sig_alg = sig_alg;
		}
	}

	if (signature_algorithms_cert && signature_algorithms_cert_cnt) {
		if ((ret = tls_cert_chain_match_signature_algorithms_cert(cert_chain, cert_chain_len,
			signature_algorithms_cert, signature_algorithms_cert_cnt)) < 0) {
			error_print();
			tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
			return -1;
		}
		if (ret == 0) {
			error_print();
			tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
			return 0;
		}
	}

	if (ca_names && ca_names_len) {
		if ((ret = tls_authorities_issued_certificate(ca_names, ca_names_len,
			cert_chain, cert_chain_len)) < 0) {
			error_print();
			tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
			return -1;
		}
		if (ret == 0) {
			error_print();
			tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
			return 0;
		}
	}

	return tls_cert_chain_check_name(cert_chain, cert_chain_len,
		host_name, host_name_len, verify_result);
}

static int tlcp_cert_chain_match(
	int cert_chain_type, int cipher_suite,
	const uint8_t *cert_chain, size_t cert_chain_len,
	const int *signature_algorithms, size_t signature_algorithms_cnt,
	const uint8_t *ca_names, size_t ca_names_len,
	const uint8_t *host_name, size_t host_name_len,
	int *verify_result, int *selected_sig_alg)
{
	int ret;

	switch (cipher_suite) {
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecc_sm4_gcm_sm3:
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
		break;
	default:
		error_print();
		tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
		return 0;
	}

	if (signature_algorithms && signature_algorithms_cnt) {
		if (!tls_type_is_in_list(TLS_sig_sm2sig_sm3,
			signature_algorithms, signature_algorithms_cnt)) {
			error_print();
			tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
			return 0;
		}
	}
	if (selected_sig_alg) {
		*selected_sig_alg = TLS_sig_sm2sig_sm3;
	}

	if (ca_names && ca_names_len) {
		if ((ret = tls_authorities_issued_certificate(ca_names, ca_names_len,
			cert_chain, cert_chain_len)) < 0) {
			error_print();
			tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
			return -1;
		}
		if (ret == 0) {
			error_print();
			tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
			return 0;
		}
	}

	if (cert_chain_type == X509_cert_chain_server) {
		return tls_cert_chain_check_name(cert_chain, cert_chain_len,
			host_name, host_name_len, verify_result);
	}
	return 1;
}

static int tls13_cert_chain_match(
	const uint8_t *cert_chain, size_t cert_chain_len,
	const int *signature_algorithms, size_t signature_algorithms_cnt,
	const int *signature_algorithms_cert, size_t signature_algorithms_cert_cnt,
	const uint8_t *ca_names, size_t ca_names_len,
	const uint8_t *oid_filters, size_t oid_filters_len,
	const uint8_t *host_name, size_t host_name_len,
	int *verify_result, int *selected_sig_alg)
{
	int ret;

	if ((ret = tls_cert_chain_check_name(cert_chain, cert_chain_len,
		host_name, host_name_len, verify_result)) != 1) {
		return ret;
	}
	if ((ret = tls_cert_chain_match_extensions(cert_chain, cert_chain_len,
		signature_algorithms, signature_algorithms_cnt,
		signature_algorithms_cert, signature_algorithms_cert_cnt,
		ca_names, ca_names_len,
		oid_filters, oid_filters_len,
		NULL, 0,
		selected_sig_alg)) < 0) {
		error_print();
		tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
		return -1;
	}
	if (ret == 0) {
		error_print();
		tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
		return 0;
	}
	return 1;
}

int tls_cert_chain_verify(
	int protocol, int cert_chain_type, int cipher_suite,
	int verify_chain,
	const uint8_t *cert_chain, size_t cert_chain_len,
	const uint8_t *cacerts, size_t cacerts_len,
	const uint8_t *crl, size_t crl_len,
	const uint8_t *ocsp, size_t ocsp_len,
	int verify_depth,
	const int *supported_groups, size_t supported_groups_cnt,
	const int *signature_algorithms, size_t signature_algorithms_cnt,
	const int *signature_algorithms_cert, size_t signature_algorithms_cert_cnt,
	const uint8_t *ca_names, size_t ca_names_len,
	const uint8_t *oid_filters, size_t oid_filters_len,
	const uint8_t *host_name, size_t host_name_len,
	int *verify_result,
	int *selected_sig_alg)
{
	int ret;

	if (!cert_chain || !cert_chain_len) {
		error_print();
		tls_cert_verify_set_result(verify_result, X509_verify_err_certificate);
		return -1;
	}
	if (selected_sig_alg) {
		*selected_sig_alg = 0;
	}
	tls_cert_verify_set_result(verify_result, X509_verify_ok);

	switch (protocol) {
	case TLS_protocol_tls12:
		ret = tls12_cert_chain_match(cert_chain_type, cipher_suite,
			cert_chain, cert_chain_len,
			supported_groups, supported_groups_cnt,
			signature_algorithms, signature_algorithms_cnt,
			signature_algorithms_cert, signature_algorithms_cert_cnt,
			ca_names, ca_names_len,
			host_name, host_name_len,
			verify_result, selected_sig_alg);
		break;
	case TLS_protocol_tlcp:
		ret = tlcp_cert_chain_match(cert_chain_type, cipher_suite,
			cert_chain, cert_chain_len,
			signature_algorithms, signature_algorithms_cnt,
			ca_names, ca_names_len,
			host_name, host_name_len,
			verify_result, selected_sig_alg);
		break;
	case TLS_protocol_tls13:
		ret = tls13_cert_chain_match(cert_chain, cert_chain_len,
			signature_algorithms, signature_algorithms_cnt,
			signature_algorithms_cert, signature_algorithms_cert_cnt,
			ca_names, ca_names_len,
			oid_filters, oid_filters_len,
			host_name, host_name_len,
			verify_result, selected_sig_alg);
		break;
	default:
		error_print();
		tls_cert_verify_set_result(verify_result, X509_verify_err_tls_extensions);
		return -1;
	}
	if (ret < 0) {
		error_print();
		return -1;
	}
	if (ret == 0) {
		error_print();
		return 0;
	}

	if (verify_chain) {
		if (protocol == TLS_protocol_tlcp
			&& (cert_chain_type == X509_cert_chain_server
				|| (cert_chain_type == X509_cert_chain_client
					&& tls_cipher_suite_is_tlcp_ecdhe(cipher_suite)))) {
			ret = x509_certs_verify_tlcp(cert_chain, cert_chain_len, cert_chain_type,
				cacerts, cacerts_len, crl, crl_len, ocsp, ocsp_len,
				verify_depth, verify_result);
		} else {
			ret = x509_certs_verify(cert_chain, cert_chain_len, cert_chain_type,
				cacerts, cacerts_len, crl, crl_len, ocsp, ocsp_len,
				verify_depth, verify_result);
		}
		if (ret < 0) {
			error_print();
			return -1;
		}
		if (ret == 0) {
			error_print();
			return 0;
		}
	}

	tls_cert_verify_set_result(verify_result, X509_verify_ok);
	return 1;
}
