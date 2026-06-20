include("${CMAKE_CURRENT_LIST_DIR}/tool_helpers.cmake")

file(READ sm2_tls_server_cert.pem OCSP_CERT)
file(READ sm2_tls_server_ca2_cert.pem OCSP_ISSUER)
file(WRITE tool_ocsp_chain.pem "${OCSP_CERT}${OCSP_ISSUER}")

gmssl_run(ocspreq
	-in tool_ocsp_chain.pem
	-digest sm3
	-out tool_ocsp_req.der
	-verbose)
gmssl_require_file(tool_ocsp_req.der)

gmssl_run(ocspsign
	-reqin tool_ocsp_req.der
	-cacert sm2_tls_server_ca2_cert.pem
	-signer sm2_ocsp_responder_cert.pem
	-key sm2_ocsp_responder_key.pem
	-pass P@ssw0rd
	-status good
	-certs sm2_ocsp_responder_cert.pem
	-out tool_ocsp_resp.der
	-verbose)
gmssl_require_file(tool_ocsp_resp.der)

gmssl_expect_stdout("Verification success\n"
	ocspverify
	-reqin tool_ocsp_req.der
	-respin tool_ocsp_resp.der
	-cacert sm2_tls_server_ca2_cert.pem
	-signer sm2_ocsp_responder_cert.pem
	-certs sm2_ocsp_responder_cert.pem
	-clock_skew 300
	-verbose)
