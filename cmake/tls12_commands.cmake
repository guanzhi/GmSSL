include("${CMAKE_CURRENT_LIST_DIR}/tls_command_test.cmake")

gmssl_require_file(sm2_root_ca_cert.pem)
gmssl_require_file(sm2_tls_server_certs.pem)
gmssl_require_file(sm2_tls_server_key.pem)

if(NOT DEFINED TEST_CASE)
	set(TEST_CASE tls12_sm4_cbc)
endif()

if(TEST_CASE STREQUAL tls12_sm4_cbc)
	set(TEST_NAME tls12_sm4_cbc)
	set(TEST_PORT 4432)
	set(TEST_CIPHER_SUITE TLS_ECDHE_SM4_CBC_SM3)
elseif(TEST_CASE STREQUAL tls12_sm4_gcm)
	set(TEST_NAME tls12_sm4_gcm)
	set(TEST_PORT 4434)
	set(TEST_CIPHER_SUITE TLS_ECDHE_SM4_GCM_SM3)
else()
	message(FATAL_ERROR "unknown TLS 1.2 test case: ${TEST_CASE}")
endif()

gmssl_run_tls_command_test(
	TEST_NAME ${TEST_NAME}
	PORT ${TEST_PORT}
	SERVER_ARGS
		tls12_server
		-port ${TEST_PORT}
		-cert sm2_tls_server_certs.pem
		-key sm2_tls_server_key.pem
		-pass P@ssw0rd
		-cipher_suite ${TEST_CIPHER_SUITE}
		-supported_group sm2p256v1
		-sig_alg sm2sig_sm3
	CLIENT_ARGS
		tls12_client
		-host 127.0.0.1
		-port ${TEST_PORT}
		-server_name localhost
		-cacert sm2_root_ca_cert.pem
		-cipher_suite ${TEST_CIPHER_SUITE}
		-supported_group sm2p256v1
		-sig_alg sm2sig_sm3
		-in ${TEST_NAME}_message.txt
)
