set(GMSSL_TEST_PASS P@ssw0rd)
set(GMSSL_TEST_SUBJECT -C CN -ST Beijing -L Haidian -O GmSSL -OU Test)

function(gmssl_run)
	execute_process(
		COMMAND ${ARGN}
		RESULT_VARIABLE TEST_RESULT
		ERROR_VARIABLE TEST_STDERR
	)
	if(NOT ${TEST_RESULT} EQUAL 0)
		message(FATAL_ERROR "command failed: ${ARGN}\nstderr: ${TEST_STDERR}")
	endif()
endfunction()

function(gmssl_require_generated_file file)
	if(NOT EXISTS "${file}")
		message(FATAL_ERROR "generated file does not exist: ${file}")
	endif()
endfunction()

function(gmssl_read_generated_pem file expected_header)
	gmssl_require_generated_file("${file}")
	file(READ "${file}" FILE_CONTENT)
	if(NOT FILE_CONTENT MATCHES "^${expected_header}")
		message(FATAL_ERROR "generated file has unexpected PEM header: ${file}")
	endif()
endfunction()

function(gmssl_generate_sm2_key key_file)
	gmssl_run(bin/gmssl sm2keygen -pass ${GMSSL_TEST_PASS} -out "${key_file}")
	gmssl_require_generated_file("${key_file}")
endfunction()

function(gmssl_generate_p256_key key_file export_file)
	if(export_file)
		gmssl_run(bin/gmssl p256keygen -pass ${GMSSL_TEST_PASS} -out "${key_file}" -export "${export_file}")
		gmssl_require_generated_file("${export_file}")
	else()
		gmssl_run(bin/gmssl p256keygen -pass ${GMSSL_TEST_PASS} -out "${key_file}")
	endif()
	gmssl_require_generated_file("${key_file}")
endfunction()

function(gmssl_generate_key alg key_file export_file)
	if(alg STREQUAL SM2)
		gmssl_generate_sm2_key("${key_file}")
	elseif(alg STREQUAL P256)
		gmssl_generate_p256_key("${key_file}" "${export_file}")
	else()
		message(FATAL_ERROR "unknown key algorithm: ${alg}")
	endif()
endfunction()

function(gmssl_x509_sig_alg alg out_var)
	if(alg STREQUAL SM2)
		set(${out_var} sm2sign-with-sm3 PARENT_SCOPE)
	elseif(alg STREQUAL P256)
		set(${out_var} ecdsa-with-sha256 PARENT_SCOPE)
	else()
		message(FATAL_ERROR "unknown key algorithm: ${alg}")
	endif()
endfunction()

function(gmssl_generate_root_ca alg prefix common_name)
	gmssl_generate_key(${alg} "${prefix}_key.pem" "${prefix}_key.exp")
	gmssl_x509_sig_alg(${alg} sig_alg)
	gmssl_run(bin/gmssl certgen
		${GMSSL_TEST_SUBJECT}
		-CN "${common_name}"
		-days 3650
		-key "${prefix}_key.pem"
		-pass ${GMSSL_TEST_PASS}
		-sig_alg ${sig_alg}
		-out "${prefix}_cert.pem"
		-key_usage keyCertSign
		-key_usage cRLSign
		-ca)
	gmssl_read_generated_pem("${prefix}_cert.pem" "-----BEGIN CERTIFICATE-----")
endfunction()

function(gmssl_generate_ca alg prefix common_name issuer_cert issuer_key path_len)
	gmssl_generate_key(${alg} "${prefix}_key.pem" "${prefix}_key.exp")
	gmssl_x509_sig_alg(${alg} sig_alg)
	gmssl_run(bin/gmssl reqgen
		${GMSSL_TEST_SUBJECT}
		-CN "${common_name}"
		-key "${prefix}_key.pem"
		-pass ${GMSSL_TEST_PASS}
		-sig_alg ${sig_alg}
		-out "${prefix}_req.pem")
	gmssl_read_generated_pem("${prefix}_req.pem" "-----BEGIN CERTIFICATE REQUEST-----")
	gmssl_run(bin/gmssl reqsign
		-in "${prefix}_req.pem"
		-days 1825
		-key_usage keyCertSign
		-key_usage cRLSign
		-path_len_constraint ${path_len}
		-cacert "${issuer_cert}"
		-key "${issuer_key}"
		-pass ${GMSSL_TEST_PASS}
		-sig_alg ${sig_alg}
		-out "${prefix}_cert.pem"
		-ca)
	gmssl_read_generated_pem("${prefix}_cert.pem" "-----BEGIN CERTIFICATE-----")
endfunction()

function(gmssl_generate_end_entity alg prefix common_name issuer_cert issuer_key key_usage ext_key_usage subject_dns_name export_key)
	if(export_key)
		set(export_file "${prefix}_key.exp")
	else()
		set(export_file "")
	endif()
	gmssl_generate_key(${alg} "${prefix}_key.pem" "${export_file}")
	gmssl_x509_sig_alg(${alg} sig_alg)
	gmssl_run(bin/gmssl reqgen
		${GMSSL_TEST_SUBJECT}
		-CN "${common_name}"
		-key "${prefix}_key.pem"
		-pass ${GMSSL_TEST_PASS}
		-sig_alg ${sig_alg}
		-out "${prefix}_req.pem")
	gmssl_read_generated_pem("${prefix}_req.pem" "-----BEGIN CERTIFICATE REQUEST-----")

	set(sign_args
		-in "${prefix}_req.pem"
		-days 365
		-key_usage ${key_usage}
		-cacert "${issuer_cert}"
		-key "${issuer_key}"
		-pass ${GMSSL_TEST_PASS}
		-sig_alg ${sig_alg}
		-out "${prefix}_cert.pem")
	if(ext_key_usage)
		list(APPEND sign_args -ext_key_usage ${ext_key_usage})
	endif()
	if(subject_dns_name)
		list(APPEND sign_args -subject_dns_name ${subject_dns_name})
	endif()
	gmssl_run(bin/gmssl reqsign ${sign_args})
	gmssl_read_generated_pem("${prefix}_cert.pem" "-----BEGIN CERTIFICATE-----")
endfunction()

function(gmssl_write_bundle out_file)
	file(WRITE "${out_file}" "")
	foreach(pem_file IN LISTS ARGN)
		gmssl_require_generated_file("${pem_file}")
		file(READ "${pem_file}" PEM_CONTENT)
		file(APPEND "${out_file}" "${PEM_CONTENT}")
	endforeach()
	gmssl_require_generated_file("${out_file}")
endfunction()

# Root CAs
gmssl_generate_root_ca(SM2 sm2_root_ca "GmSSL SM2 Test Root CA")
gmssl_generate_root_ca(P256 p256_root_ca "GmSSL P256 Test Root CA")

# SM2 TLS server chain: root -> server CA 1 -> server CA 2 -> server certificate
gmssl_generate_ca(SM2 sm2_tls_server_ca1 "GmSSL SM2 TLS Server CA 1"
	sm2_root_ca_cert.pem sm2_root_ca_key.pem 1)
gmssl_generate_ca(SM2 sm2_tls_server_ca2 "GmSSL SM2 TLS Server CA 2"
	sm2_tls_server_ca1_cert.pem sm2_tls_server_ca1_key.pem 0)
gmssl_generate_end_entity(SM2 sm2_tls_server "GmSSL SM2 TLS Server"
	sm2_tls_server_ca2_cert.pem sm2_tls_server_ca2_key.pem
	digitalSignature serverAuth localhost OFF)
gmssl_write_bundle(sm2_tls_server_certs.pem
	sm2_tls_server_cert.pem sm2_tls_server_ca2_cert.pem sm2_tls_server_ca1_cert.pem)

# P256 TLS server chain: root -> server CA 1 -> server CA 2 -> server certificate
gmssl_generate_ca(P256 p256_tls_server_ca1 "GmSSL P256 TLS Server CA 1"
	p256_root_ca_cert.pem p256_root_ca_key.pem 1)
gmssl_generate_ca(P256 p256_tls_server_ca2 "GmSSL P256 TLS Server CA 2"
	p256_tls_server_ca1_cert.pem p256_tls_server_ca1_key.pem 0)
gmssl_generate_end_entity(P256 p256_tls_server "GmSSL P256 TLS Server"
	p256_tls_server_ca2_cert.pem p256_tls_server_ca2_key.pem
	digitalSignature serverAuth localhost ON)
gmssl_write_bundle(p256_tls_server_certs.pem
	p256_tls_server_cert.pem p256_tls_server_ca2_cert.pem p256_tls_server_ca1_cert.pem)
gmssl_write_bundle(p256_tls_server_cert_chain.pem
	p256_tls_server_ca2_cert.pem p256_tls_server_ca1_cert.pem)

# SM2 TLS client chain: root -> client CA -> client certificate
gmssl_generate_ca(SM2 sm2_tls_client_ca "GmSSL SM2 TLS Client CA"
	sm2_root_ca_cert.pem sm2_root_ca_key.pem 0)
gmssl_generate_end_entity(SM2 sm2_tls_client "GmSSL SM2 TLS Client"
	sm2_tls_client_ca_cert.pem sm2_tls_client_ca_key.pem
	digitalSignature clientAuth "" OFF)
gmssl_write_bundle(sm2_tls_client_certs.pem
	sm2_tls_client_cert.pem sm2_tls_client_ca_cert.pem)

# SM2 TLCP client chain reuses the SM2 TLS client CA and adds an encryption certificate.
gmssl_generate_end_entity(SM2 sm2_tlcp_client_sign "GmSSL SM2 TLCP Client"
	sm2_tls_client_ca_cert.pem sm2_tls_client_ca_key.pem
	digitalSignature clientAuth "" OFF)
gmssl_generate_end_entity(SM2 sm2_tlcp_client_enc "GmSSL SM2 TLCP Client"
	sm2_tls_client_ca_cert.pem sm2_tls_client_ca_key.pem
	keyEncipherment clientAuth "" OFF)
gmssl_write_bundle(sm2_tlcp_client_certs.pem
	sm2_tlcp_client_sign_cert.pem
	sm2_tlcp_client_enc_cert.pem
	sm2_tls_client_ca_cert.pem)
gmssl_write_bundle(sm2_tlcp_client_keys.pem
	sm2_tlcp_client_sign_key.pem sm2_tlcp_client_enc_key.pem)

# P256 TLS client chain: root -> client CA -> client certificate
gmssl_generate_ca(P256 p256_tls_client_ca "GmSSL P256 TLS Client CA"
	p256_root_ca_cert.pem p256_root_ca_key.pem 0)
gmssl_generate_end_entity(P256 p256_tls_client "GmSSL P256 TLS Client"
	p256_tls_client_ca_cert.pem p256_tls_client_ca_key.pem
	digitalSignature clientAuth "" ON)
gmssl_write_bundle(p256_tls_client_certs.pem
	p256_tls_client_cert.pem p256_tls_client_ca_cert.pem)

# OCSP delegated responders for certificates issued by the TLS server CA2s.
gmssl_generate_end_entity(SM2 sm2_ocsp_responder "GmSSL SM2 OCSP Responder"
	sm2_tls_server_ca2_cert.pem sm2_tls_server_ca2_key.pem
	digitalSignature OCSPSigning "" OFF)
gmssl_generate_end_entity(P256 p256_ocsp_responder "GmSSL P256 OCSP Responder"
	p256_tls_server_ca2_cert.pem p256_tls_server_ca2_key.pem
	digitalSignature OCSPSigning "" ON)

# TLCP server chain reuses the SM2 TLS server CA chain and adds an encryption certificate.
gmssl_generate_end_entity(SM2 sm2_tlcp_server_sign "GmSSL SM2 TLCP Server"
	sm2_tls_server_ca2_cert.pem sm2_tls_server_ca2_key.pem
	digitalSignature serverAuth localhost OFF)
gmssl_generate_end_entity(SM2 sm2_tlcp_server_enc "GmSSL SM2 TLCP Server"
	sm2_tls_server_ca2_cert.pem sm2_tls_server_ca2_key.pem
	keyEncipherment serverAuth localhost OFF)
gmssl_write_bundle(sm2_tlcp_server_certs.pem
	sm2_tlcp_server_sign_cert.pem
	sm2_tlcp_server_enc_cert.pem
	sm2_tls_server_ca2_cert.pem
	sm2_tls_server_ca1_cert.pem)
gmssl_write_bundle(sm2_tlcp_server_keys.pem
	sm2_tlcp_server_sign_key.pem sm2_tlcp_server_enc_key.pem)

gmssl_write_bundle(test_root_certs.pem
	sm2_root_ca_cert.pem p256_root_ca_cert.pem)

gmssl_run(bin/gmssl certparse -in sm2_tlcp_server_certs.pem -out tool_certparse.txt)
gmssl_require_generated_file(tool_certparse.txt)

gmssl_run(bin/gmssl certverify
	-tlcp_server
	-in sm2_tlcp_server_certs.pem
	-cacert sm2_root_ca_cert.pem
	-hostname localhost)

gmssl_run(bin/gmssl certverify
	-server
	-in sm2_tls_server_certs.pem
	-cacert sm2_root_ca_cert.pem
	-hostname LOCALHOST)

gmssl_run(bin/gmssl certverify
	-client
	-in sm2_tls_client_certs.pem
	-cacert sm2_root_ca_cert.pem)
