include("${CMAKE_CURRENT_LIST_DIR}/tool_helpers.cmake")

gmssl_run(certrevoke
	-in sm2_tls_server_cert.pem
	-reason keyCompromise
	-invalid_date 20260101000000Z
	-out tool_revoked_certs.der)
gmssl_require_file(tool_revoked_certs.der)

gmssl_run(crlgen
	-in tool_revoked_certs.der
	-cacert sm2_tls_server_ca2_cert.pem
	-key sm2_tls_server_ca2_key.pem
	-pass P@ssw0rd
	-next_update 20270101000000Z
	-gen_authority_key_id
	-crl_num 1
	-out tool_crl.der)
gmssl_require_file(tool_crl.der)

gmssl_run(crlparse -in tool_crl.der -out tool_crl.txt)
gmssl_require_file(tool_crl.txt)

gmssl_expect_stdout("Verification success\n"
	crlverify -in tool_crl.der -cacert sm2_tls_server_ca2_cert.pem)
