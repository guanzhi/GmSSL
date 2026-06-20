include("${CMAKE_CURRENT_LIST_DIR}/tls_command_test.cmake")

gmssl_require_file(sm2_root_ca_cert.pem)
gmssl_require_file(sm2_tls_server_certs.pem)
gmssl_require_file(sm2_tls_server_key.pem)
gmssl_require_file(sm2_tls_client_certs.pem)
gmssl_require_file(sm2_tls_client_key.pem)

if(NOT DEFINED TEST_CASE)
	set(TEST_CASE tls12_sm4_gcm_sni)
endif()

if(TEST_CASE STREQUAL tls12_sm4_gcm_sni)
	set(TEST_NAME tls12_sm4_gcm_sni)
	set(TEST_PORT 4434)
	set(TEST_CIPHER_SUITE TLS_ECDHE_SM4_GCM_SM3)
	set(TEST_CLIENT_CERT OFF)
elseif(TEST_CASE STREQUAL tls12_sm4_gcm_renegotiation_info)
	set(TEST_NAME tls12_sm4_gcm_renegotiation_info)
	set(TEST_PORT 4461)
	set(TEST_CIPHER_SUITE TLS_ECDHE_SM4_GCM_SM3)
	set(TEST_CLIENT_CERT OFF)
	set(TEST_RENEGOTIATION_ARG -renegotiation_info)
elseif(TEST_CASE STREQUAL tls12_sm4_gcm_renegotiation_info_scsv)
	set(TEST_NAME tls12_sm4_gcm_renegotiation_info_scsv)
	set(TEST_PORT 4462)
	set(TEST_CIPHER_SUITE TLS_ECDHE_SM4_GCM_SM3)
	set(TEST_CLIENT_CERT OFF)
	set(TEST_RENEGOTIATION_ARG -renegotiation_info_scsv)
elseif(TEST_CASE STREQUAL tls12_sm4_cbc_sni)
	set(TEST_NAME tls12_sm4_cbc_sni)
	set(TEST_PORT 4432)
	set(TEST_CIPHER_SUITE TLS_ECDHE_SM4_CBC_SM3)
	set(TEST_CLIENT_CERT OFF)
elseif(TEST_CASE STREQUAL tls12_sm4_gcm_client_cert)
	set(TEST_NAME tls12_sm4_gcm_client_cert)
	set(TEST_PORT 4438)
	set(TEST_CIPHER_SUITE TLS_ECDHE_SM4_GCM_SM3)
	set(TEST_CLIENT_CERT ON)
else()
	message(FATAL_ERROR "unknown TLS 1.2 test case: ${TEST_CASE}")
endif()

set(TEST_SERVER_ARGS
	tls12_server
	-port ${TEST_PORT}
	-cipher_suite ${TEST_CIPHER_SUITE}
	-supported_group sm2p256v1
	-sig_alg sm2sig_sm3
	-cert sm2_tls_server_certs.pem
	-key sm2_tls_server_key.pem
	-pass P@ssw0rd)

set(TEST_CLIENT_ARGS
	tls12_client
	-host 127.0.0.1
	-port ${TEST_PORT}
	-server_name localhost
	-cacert sm2_root_ca_cert.pem
	-cipher_suite ${TEST_CIPHER_SUITE}
	-supported_group sm2p256v1
	-sig_alg sm2sig_sm3
	-in ${TEST_NAME}_message.txt)

if(TEST_RENEGOTIATION_ARG)
	list(APPEND TEST_CLIENT_ARGS ${TEST_RENEGOTIATION_ARG})
endif()

if(TEST_CLIENT_CERT)
	list(APPEND TEST_SERVER_ARGS
		-cacert sm2_root_ca_cert.pem
		-cert_request)
	list(APPEND TEST_CLIENT_ARGS
		-cert sm2_tls_client_certs.pem
		-key sm2_tls_client_key.pem
		-pass P@ssw0rd)
endif()

gmssl_run_tls_command_test(
	TEST_NAME ${TEST_NAME}
	PORT ${TEST_PORT}
	SERVER_ARGS ${TEST_SERVER_ARGS}
	CLIENT_ARGS ${TEST_CLIENT_ARGS}
)
