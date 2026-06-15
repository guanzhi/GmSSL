include("${CMAKE_CURRENT_LIST_DIR}/tls_command_test.cmake")

if(NOT DEFINED OPENSSL_EXECUTABLE)
	find_program(OPENSSL_EXECUTABLE openssl)
endif()
if(NOT OPENSSL_EXECUTABLE)
	message(FATAL_ERROR "openssl executable not found")
endif()

gmssl_require_file(p256rootcacert.pem)
gmssl_require_file(p256cacert.pem)
gmssl_require_file(p256signcert.pem)
gmssl_require_file(p256certs.pem)
gmssl_require_file(p256signkey.pem)
gmssl_require_file(p256signkey.exp)

if(NOT DEFINED TEST_CASE)
	set(TEST_CASE tls12_openssl_server)
endif()

if(TEST_CASE STREQUAL tls12_openssl_server)
	set(TEST_NAME tls12_openssl_server)
	set(TEST_PORT 4450)
	set(SERVER_COMMAND "${OPENSSL_EXECUTABLE} s_server -accept ${TEST_PORT} -cert p256signcert.pem -cert_chain p256cacert.pem -key p256signkey.exp -tls1_2 -cipher ECDHE-ECDSA-AES128-SHA256 -named_curve prime256v1 -www -naccept 1 -quiet")
	set(CLIENT_COMMAND "bin/gmssl tls12_client -host 127.0.0.1 -port ${TEST_PORT} -server_name 127.0.0.1 -cacert p256rootcacert.pem -cipher_suite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256 -get /")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "Connection established")
elseif(TEST_CASE STREQUAL tls12_openssl_client)
	set(TEST_NAME tls12_openssl_client)
	set(TEST_PORT 4451)
	set(SERVER_COMMAND "bin/gmssl tls12_server -port ${TEST_PORT} -cert p256certs.pem -key p256signkey.pem -pass P@ssw0rd -cipher_suite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256 -renegotiation_info")
	set(CLIENT_COMMAND "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | ${OPENSSL_EXECUTABLE} s_client -connect 127.0.0.1:${TEST_PORT} -tls1_2 -CAfile p256rootcacert.pem -cipher ECDHE-ECDSA-AES128-SHA256 -groups prime256v1 -servername 127.0.0.1 -brief")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "Verification: OK")
elseif(TEST_CASE STREQUAL tls13_openssl_server)
	set(TEST_NAME tls13_openssl_server)
	set(TEST_PORT 4452)
	set(SERVER_COMMAND "${OPENSSL_EXECUTABLE} s_server -accept ${TEST_PORT} -cert p256signcert.pem -cert_chain p256cacert.pem -key p256signkey.exp -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups prime256v1 -no_middlebox -www -naccept 1 -quiet")
	set(CLIENT_COMMAND "bin/gmssl tls13_client -host 127.0.0.1 -port ${TEST_PORT} -server_name 127.0.0.1 -cacert p256rootcacert.pem -cipher_suite TLS_AES_128_GCM_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256 -get /")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "Connection established")
elseif(TEST_CASE STREQUAL tls13_openssl_client)
	set(TEST_NAME tls13_openssl_client)
	set(TEST_PORT 4453)
	set(SERVER_COMMAND "bin/gmssl tls13_server -port ${TEST_PORT} -cert p256certs.pem -key p256signkey.pem -pass P@ssw0rd -cipher_suite TLS_AES_128_GCM_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256")
	set(CLIENT_COMMAND "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | ${OPENSSL_EXECUTABLE} s_client -connect 127.0.0.1:${TEST_PORT} -tls1_3 -CAfile p256rootcacert.pem -ciphersuites TLS_AES_128_GCM_SHA256 -groups prime256v1 -sigalgs ecdsa_secp256r1_sha256 -no_middlebox -brief")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "Verification: OK")
else()
	message(FATAL_ERROR "unknown OpenSSL interop test case: ${TEST_CASE}")
endif()
