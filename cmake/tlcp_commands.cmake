include("${CMAKE_CURRENT_LIST_DIR}/tls_command_test.cmake")

gmssl_require_file(sm2_root_ca_cert.pem)
gmssl_require_file(sm2_tlcp_server_certs.pem)
gmssl_require_file(sm2_tlcp_server_keys.pem)
gmssl_require_file(sm2_tls_client_certs.pem)
gmssl_require_file(sm2_tls_client_key.pem)

if(NOT DEFINED TEST_CASE)
	set(TEST_CASE tlcp_sm4_gcm_sni)
endif()

if(TEST_CASE STREQUAL tlcp_sm4_gcm_sni)
	set(TEST_NAME tlcp_sm4_gcm_sni)
	set(TEST_PORT 4435)
	set(TEST_CIPHER_SUITE TLS_ECC_SM4_GCM_SM3)
	set(TEST_CLIENT_CERT OFF)
elseif(TEST_CASE STREQUAL tlcp_sm4_cbc_sni)
	set(TEST_NAME tlcp_sm4_cbc_sni)
	set(TEST_PORT 4431)
	set(TEST_CIPHER_SUITE TLS_ECC_SM4_CBC_SM3)
	set(TEST_CLIENT_CERT OFF)
elseif(TEST_CASE STREQUAL tlcp_sm4_gcm_client_cert)
	set(TEST_NAME tlcp_sm4_gcm_client_cert)
	set(TEST_PORT 4436)
	set(TEST_CIPHER_SUITE TLS_ECC_SM4_GCM_SM3)
	set(TEST_CLIENT_CERT ON)
else()
	message(FATAL_ERROR "unknown TLCP test case: ${TEST_CASE}")
endif()

set(TEST_SERVER_ARGS
	tlcp_server
	-port ${TEST_PORT}
	-cipher_suite ${TEST_CIPHER_SUITE}
	-cert sm2_tlcp_server_certs.pem
	-key sm2_tlcp_server_keys.pem
	-pass P@ssw0rd)

set(TEST_CLIENT_ARGS
	tlcp_client
	-host 127.0.0.1
	-port ${TEST_PORT}
	-server_name localhost
	-cacert sm2_root_ca_cert.pem
	-cipher_suite ${TEST_CIPHER_SUITE}
	-in ${TEST_NAME}_message.txt)

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
