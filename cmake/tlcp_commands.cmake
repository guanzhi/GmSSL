include("${CMAKE_CURRENT_LIST_DIR}/tls_command_test.cmake")

gmssl_require_file(rootcacert.pem)
gmssl_require_file(tlcp_server_certs.pem)
gmssl_require_file(tlcp_server_keys.pem)

if(NOT DEFINED TEST_CASE)
	set(TEST_CASE tlcp_sm4_cbc)
endif()

if(TEST_CASE STREQUAL tlcp_sm4_cbc)
	set(TEST_NAME tlcp_sm4_cbc)
	set(TEST_PORT 4431)
	set(TEST_CIPHER_SUITE TLS_ECC_SM4_CBC_SM3)
elseif(TEST_CASE STREQUAL tlcp_sm4_gcm)
	set(TEST_NAME tlcp_sm4_gcm)
	set(TEST_PORT 4435)
	set(TEST_CIPHER_SUITE TLS_ECC_SM4_GCM_SM3)
else()
	message(FATAL_ERROR "unknown TLCP test case: ${TEST_CASE}")
endif()

gmssl_run_tls_command_test(
	TEST_NAME ${TEST_NAME}
	PORT ${TEST_PORT}
	SERVER_ARGS
		tlcp_server
		-port ${TEST_PORT}
		-cipher_suite ${TEST_CIPHER_SUITE}
		-cert tlcp_server_certs.pem
		-key tlcp_server_keys.pem
		-pass P@ssw0rd
	CLIENT_ARGS
		tlcp_client
		-host 127.0.0.1
		-port ${TEST_PORT}
		-cacert rootcacert.pem
		-cipher_suite ${TEST_CIPHER_SUITE}
		-in ${TEST_NAME}_message.txt
)
