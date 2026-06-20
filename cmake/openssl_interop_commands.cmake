include("${CMAKE_CURRENT_LIST_DIR}/tls_command_test.cmake")

if(NOT DEFINED OPENSSL_EXECUTABLE)
	find_program(OPENSSL_EXECUTABLE openssl)
endif()
if(NOT OPENSSL_EXECUTABLE)
	message(FATAL_ERROR "openssl executable not found")
endif()

gmssl_require_file(p256_root_ca_cert.pem)
gmssl_require_file(p256_tls_server_ca2_cert.pem)
gmssl_require_file(p256_tls_server_cert.pem)
gmssl_require_file(p256_tls_server_cert_chain.pem)
gmssl_require_file(p256_tls_server_certs.pem)
gmssl_require_file(p256_tls_server_key.pem)
gmssl_require_file(p256_tls_server_key.exp)

if(NOT DEFINED TEST_CASE)
	set(TEST_CASE tls12_openssl_server)
endif()

set(TLS13_PSK 1122334455667788112233445566778811223344556677881122334455667788)

if(TEST_CASE STREQUAL tls12_openssl_server)
	set(TEST_NAME tls12_openssl_server)
	set(TEST_PORT 4450)
	set(SERVER_COMMAND "${OPENSSL_EXECUTABLE} s_server -accept ${TEST_PORT} -cert p256_tls_server_cert.pem -cert_chain p256_tls_server_cert_chain.pem -key p256_tls_server_key.exp -tls1_2 -cipher ECDHE-ECDSA-AES128-SHA256 -named_curve prime256v1 -www -naccept 1 -quiet")
	set(CLIENT_COMMAND "bin/gmssl tls12_client -host 127.0.0.1 -port ${TEST_PORT} -server_name localhost -cacert p256_root_ca_cert.pem -cipher_suite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256 -get /")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "Connection established")
elseif(TEST_CASE STREQUAL tls12_openssl_server_renegotiation_info)
	set(TEST_NAME tls12_openssl_server_renegotiation_info)
	set(TEST_PORT 4459)
	set(SERVER_COMMAND "${OPENSSL_EXECUTABLE} s_server -accept ${TEST_PORT} -cert p256_tls_server_cert.pem -cert_chain p256_tls_server_cert_chain.pem -key p256_tls_server_key.exp -tls1_2 -cipher ECDHE-ECDSA-AES128-SHA256 -named_curve prime256v1 -www -naccept 1 -quiet")
	set(CLIENT_COMMAND "bin/gmssl tls12_client -host 127.0.0.1 -port ${TEST_PORT} -server_name localhost -cacert p256_root_ca_cert.pem -cipher_suite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256 -renegotiation_info -get /")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "Connection established")
elseif(TEST_CASE STREQUAL tls12_openssl_server_renegotiation_info_scsv)
	set(TEST_NAME tls12_openssl_server_renegotiation_info_scsv)
	set(TEST_PORT 4460)
	set(SERVER_COMMAND "${OPENSSL_EXECUTABLE} s_server -accept ${TEST_PORT} -cert p256_tls_server_cert.pem -cert_chain p256_tls_server_cert_chain.pem -key p256_tls_server_key.exp -tls1_2 -cipher ECDHE-ECDSA-AES128-SHA256 -named_curve prime256v1 -www -naccept 1 -quiet")
	set(CLIENT_COMMAND "bin/gmssl tls12_client -host 127.0.0.1 -port ${TEST_PORT} -server_name localhost -cacert p256_root_ca_cert.pem -cipher_suite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256 -renegotiation_info_scsv -get /")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "Connection established")
elseif(TEST_CASE STREQUAL tls12_openssl_client)
	set(TEST_NAME tls12_openssl_client)
	set(TEST_PORT 4451)
	set(SERVER_COMMAND "bin/gmssl tls12_server -port ${TEST_PORT} -cert p256_tls_server_certs.pem -key p256_tls_server_key.pem -pass P@ssw0rd -cipher_suite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256")
	set(CLIENT_COMMAND "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | ${OPENSSL_EXECUTABLE} s_client -connect 127.0.0.1:${TEST_PORT} -tls1_2 -CAfile p256_root_ca_cert.pem -cipher ECDHE-ECDSA-AES128-SHA256 -groups prime256v1 -servername localhost -brief")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "Verification: OK")
elseif(TEST_CASE STREQUAL tls13_openssl_server)
	set(TEST_NAME tls13_openssl_server)
	set(TEST_PORT 4452)
	set(SERVER_COMMAND "${OPENSSL_EXECUTABLE} s_server -accept ${TEST_PORT} -cert p256_tls_server_cert.pem -cert_chain p256_tls_server_cert_chain.pem -key p256_tls_server_key.exp -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups prime256v1 -no_middlebox -www -naccept 1 -quiet")
	set(CLIENT_COMMAND "bin/gmssl tls13_client -host 127.0.0.1 -port ${TEST_PORT} -server_name localhost -cacert p256_root_ca_cert.pem -cipher_suite TLS_AES_128_GCM_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256 -get /")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "Connection established")
elseif(TEST_CASE STREQUAL tls13_openssl_client)
	set(TEST_NAME tls13_openssl_client)
	set(TEST_PORT 4453)
	set(SERVER_COMMAND "bin/gmssl tls13_server -port ${TEST_PORT} -cert p256_tls_server_certs.pem -key p256_tls_server_key.pem -pass P@ssw0rd -cipher_suite TLS_AES_128_GCM_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256")
	set(CLIENT_COMMAND "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | ${OPENSSL_EXECUTABLE} s_client -connect 127.0.0.1:${TEST_PORT} -tls1_3 -CAfile p256_root_ca_cert.pem -ciphersuites TLS_AES_128_GCM_SHA256 -groups prime256v1 -sigalgs ecdsa_secp256r1_sha256 -servername localhost -no_middlebox -brief")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "Verification: OK")
elseif(TEST_CASE STREQUAL tls13_hrr_openssl_client)
	set(TEST_NAME tls13_hrr_openssl_client)
	set(TEST_PORT 4454)
	set(SERVER_COMMAND "bin/gmssl tls13_server -port ${TEST_PORT} -cert p256_tls_server_certs.pem -key p256_tls_server_key.pem -pass P@ssw0rd -cipher_suite TLS_AES_128_GCM_SHA256 -supported_group prime256v1 -sig_alg ecdsa_secp256r1_sha256 -verbose")
	set(CLIENT_COMMAND "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | ${OPENSSL_EXECUTABLE} s_client -connect 127.0.0.1:${TEST_PORT} -tls1_3 -CAfile p256_root_ca_cert.pem -ciphersuites TLS_AES_128_GCM_SHA256 -groups secp384r1:prime256v1 -sigalgs ecdsa_secp256r1_sha256 -servername localhost -no_middlebox -brief -msg")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "Verification: OK"
		EXPECT_SERVER_LOG "selected_group: secp256r1")
elseif(TEST_CASE STREQUAL tls13_psk_dhe_openssl_server)
	set(TEST_NAME tls13_psk_dhe_openssl_server)
	set(TEST_PORT 4455)
	set(SERVER_COMMAND "${OPENSSL_EXECUTABLE} s_server -accept ${TEST_PORT} -tls1_3 -no_middlebox -nocert -psk_identity 001 -psk ${TLS13_PSK} -ciphersuites TLS_AES_128_GCM_SHA256 -groups prime256v1 -www -naccept 1 -quiet")
	set(CLIENT_COMMAND "bin/gmssl tls13_client -host 127.0.0.1 -port ${TEST_PORT} -cipher_suite TLS_AES_128_GCM_SHA256 -supported_group prime256v1 -psk_dhe_ke -psk_identity 001 -psk_cipher_suite TLS_AES_128_GCM_SHA256 -psk_key ${TLS13_PSK} -get /")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "HTTP/1.0 200 ok")
elseif(TEST_CASE STREQUAL tls13_psk_dhe_openssl_client)
	set(TEST_NAME tls13_psk_dhe_openssl_client)
	set(TEST_PORT 4456)
	set(SERVER_COMMAND "bin/gmssl tls13_server -port ${TEST_PORT} -cert p256_tls_server_certs.pem -key p256_tls_server_key.pem -pass P@ssw0rd -cipher_suite TLS_AES_128_GCM_SHA256 -supported_group prime256v1 -psk_dhe_ke -psk_identity 001 -psk_cipher_suite TLS_AES_128_GCM_SHA256 -psk_key ${TLS13_PSK}")
	set(CLIENT_COMMAND "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | ${OPENSSL_EXECUTABLE} s_client -connect 127.0.0.1:${TEST_PORT} -tls1_3 -psk_identity 001 -psk ${TLS13_PSK} -ciphersuites TLS_AES_128_GCM_SHA256 -groups prime256v1 -no_middlebox -brief")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "CONNECTION ESTABLISHED")
elseif(TEST_CASE STREQUAL tls13_psk_only_openssl_server)
	set(TEST_NAME tls13_psk_only_openssl_server)
	set(TEST_PORT 4457)
	set(SERVER_COMMAND "${OPENSSL_EXECUTABLE} s_server -accept ${TEST_PORT} -tls1_3 -no_middlebox -allow_no_dhe_kex -nocert -psk_identity 001 -psk ${TLS13_PSK} -ciphersuites TLS_AES_128_GCM_SHA256 -www -naccept 1 -quiet")
	set(CLIENT_COMMAND "bin/gmssl tls13_client -host 127.0.0.1 -port ${TEST_PORT} -cipher_suite TLS_AES_128_GCM_SHA256 -psk_ke -psk_identity 001 -psk_cipher_suite TLS_AES_128_GCM_SHA256 -psk_key ${TLS13_PSK} -get /")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "HTTP/1.0 200 ok")
elseif(TEST_CASE STREQUAL tls13_psk_only_openssl_client)
	set(TEST_NAME tls13_psk_only_openssl_client)
	set(TEST_PORT 4458)
	set(SERVER_COMMAND "bin/gmssl tls13_server -port ${TEST_PORT} -cert p256_tls_server_certs.pem -key p256_tls_server_key.pem -pass P@ssw0rd -cipher_suite TLS_AES_128_GCM_SHA256 -psk_ke -psk_identity 001 -psk_cipher_suite TLS_AES_128_GCM_SHA256 -psk_key ${TLS13_PSK}")
	set(CLIENT_COMMAND "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | ${OPENSSL_EXECUTABLE} s_client -connect 127.0.0.1:${TEST_PORT} -tls1_3 -psk_identity 001 -psk ${TLS13_PSK} -ciphersuites TLS_AES_128_GCM_SHA256 -allow_no_dhe_kex -prefer_no_dhe_kex -no_middlebox -brief")
	gmssl_run_command_interop_test(
		TEST_NAME ${TEST_NAME}
		PORT ${TEST_PORT}
		SERVER_COMMAND "${SERVER_COMMAND}"
		CLIENT_COMMAND "${CLIENT_COMMAND}"
		EXPECT_CLIENT_LOG "CONNECTION ESTABLISHED")
else()
	message(FATAL_ERROR "unknown OpenSSL interop test case: ${TEST_CASE}")
endif()
