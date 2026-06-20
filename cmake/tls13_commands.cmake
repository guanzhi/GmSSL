include("${CMAKE_CURRENT_LIST_DIR}/tls_command_test.cmake")

gmssl_require_file(sm2_root_ca_cert.pem)
gmssl_require_file(sm2_tls_server_certs.pem)
gmssl_require_file(sm2_tls_server_key.pem)
gmssl_require_file(sm2_tls_client_certs.pem)
gmssl_require_file(sm2_tls_client_key.pem)

set(TLS13_PSK 1122334455667788112233445566778811223344556677881122334455667788)

if(NOT DEFINED TEST_CASE)
	set(TEST_CASE tls13_sm4_gcm_sni)
endif()

if(TEST_CASE STREQUAL tls13_sm4_gcm_sni)
	set(TEST_NAME tls13_sm4_gcm_sni)
	set(TEST_PORT 4433)
	set(TEST_CLIENT_CERT OFF)
elseif(TEST_CASE STREQUAL tls13_sm4_gcm_client_cert)
	set(TEST_NAME tls13_sm4_gcm_client_cert)
	set(TEST_PORT 4439)
	set(TEST_CLIENT_CERT ON)
endif()

if(DEFINED TEST_NAME)
	set(TEST_SERVER_ARGS
		tls13_server
		-port ${TEST_PORT}
		-cipher_suite TLS_SM4_GCM_SM3
		-supported_group sm2p256v1
		-sig_alg sm2sig_sm3
		-cert sm2_tls_server_certs.pem
		-key sm2_tls_server_key.pem
		-pass P@ssw0rd)

	set(TEST_CLIENT_ARGS
		tls13_client
		-host 127.0.0.1
		-port ${TEST_PORT}
		-server_name localhost
		-cacert sm2_root_ca_cert.pem
		-cipher_suite TLS_SM4_GCM_SM3
		-supported_group sm2p256v1
		-sig_alg sm2sig_sm3
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
elseif(TEST_CASE STREQUAL tls13_hrr_sm4_gcm)
	gmssl_run_tls_command_test(
		TEST_NAME tls13_hrr_sm4_gcm
		PORT 4460
		EXPECT_CLIENT_LOG "selected_group: sm2p256v1"
		SERVER_ARGS
			tls13_server
			-port 4460
			-cert sm2_tls_server_certs.pem
			-key sm2_tls_server_key.pem
			-pass P@ssw0rd
			-cipher_suite TLS_SM4_GCM_SM3
			-supported_group sm2p256v1
			-sig_alg sm2sig_sm3
			-verbose
		CLIENT_ARGS
			tls13_client
			-host 127.0.0.1
			-port 4460
			-server_name localhost
			-cacert sm2_root_ca_cert.pem
			-cipher_suite TLS_SM4_GCM_SM3
			-supported_group prime256v1
			-supported_group sm2p256v1
			-sig_alg sm2sig_sm3
			-max_key_exchanges 1
			-in tls13_hrr_sm4_gcm_message.txt
			-verbose
	)
elseif(TEST_CASE STREQUAL tls13_psk_dhe_sm4_gcm)
	gmssl_run_tls_command_test(
		TEST_NAME tls13_psk_dhe_sm4_gcm
		PORT 4437
		SERVER_ARGS
			tls13_server
			-port 4437
			-cert sm2_tls_server_certs.pem
			-key sm2_tls_server_key.pem
			-pass P@ssw0rd
			-cipher_suite TLS_SM4_GCM_SM3
			-supported_group sm2p256v1
			-psk_dhe_ke
			-psk_identity 001
			-psk_cipher_suite TLS_SM4_GCM_SM3
			-psk_key ${TLS13_PSK}
		CLIENT_ARGS
			tls13_client
			-host 127.0.0.1
			-port 4437
			-cipher_suite TLS_SM4_GCM_SM3
			-supported_group sm2p256v1
			-psk_dhe_ke
			-psk_identity 001
			-psk_cipher_suite TLS_SM4_GCM_SM3
			-psk_key ${TLS13_PSK}
			-in tls13_psk_dhe_sm4_gcm_message.txt
	)
elseif(TEST_CASE STREQUAL tls13_psk_only_sm4_gcm)
	gmssl_run_tls_command_test(
		TEST_NAME tls13_psk_only_sm4_gcm
		PORT 4461
		SERVER_ARGS
			tls13_server
			-port 4461
			-cert sm2_tls_server_certs.pem
			-key sm2_tls_server_key.pem
			-pass P@ssw0rd
			-cipher_suite TLS_SM4_GCM_SM3
			-psk_ke
			-psk_identity 001
			-psk_cipher_suite TLS_SM4_GCM_SM3
			-psk_key ${TLS13_PSK}
		CLIENT_ARGS
			tls13_client
			-host 127.0.0.1
			-port 4461
			-cipher_suite TLS_SM4_GCM_SM3
			-psk_ke
			-psk_identity 001
			-psk_cipher_suite TLS_SM4_GCM_SM3
			-psk_key ${TLS13_PSK}
			-in tls13_psk_only_sm4_gcm_message.txt
	)
elseif(TEST_CASE STREQUAL tls13_early_data_sm4_gcm)
	gmssl_run_tls_command_test(
		TEST_NAME tls13_early_data_sm4_gcm
		PORT 4462
		EXPECT_SERVER_LOG "EarlyData"
		SERVER_ARGS
			tls13_server
			-port 4462
			-cert sm2_tls_server_certs.pem
			-key sm2_tls_server_key.pem
			-pass P@ssw0rd
			-cipher_suite TLS_SM4_GCM_SM3
			-psk_ke
			-psk_identity 001
			-psk_cipher_suite TLS_SM4_GCM_SM3
			-psk_key ${TLS13_PSK}
			-early_data
		CLIENT_ARGS
			tls13_client
			-host 127.0.0.1
			-port 4462
			-cipher_suite TLS_SM4_GCM_SM3
			-psk_ke
			-psk_identity 001
			-psk_cipher_suite TLS_SM4_GCM_SM3
			-psk_key ${TLS13_PSK}
			-early_data tls13_early_data_sm4_gcm_early_data.txt
			-in tls13_early_data_sm4_gcm_message.txt
	)
else()
	message(FATAL_ERROR "unknown TLS 1.3 test case: ${TEST_CASE}")
endif()
