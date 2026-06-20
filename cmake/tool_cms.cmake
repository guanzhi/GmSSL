include("${CMAKE_CURRENT_LIST_DIR}/tool_helpers.cmake")

file(WRITE tool_cms_message.txt "CMS command line test message")

gmssl_run(cmssign
	-key sm2_tls_server_key.pem
	-pass P@ssw0rd
	-cert sm2_tls_server_cert.pem
	-in tool_cms_message.txt
	-out tool_cms_signed.pem)
gmssl_require_file(tool_cms_signed.pem)

gmssl_run(cmsparse -in tool_cms_signed.pem)

gmssl_run(cmsverify
	-in tool_cms_signed.pem
	-out tool_cms_verified.txt)
gmssl_expect_file_text(tool_cms_verified.txt "CMS command line test message")

gmssl_run(cmsencrypt
	-rcptcert sm2_tlcp_server_enc_cert.pem
	-in tool_cms_message.txt
	-out tool_cms_enveloped.pem)
gmssl_require_file(tool_cms_enveloped.pem)

gmssl_run(cmsdecrypt
	-key sm2_tlcp_server_enc_key.pem
	-pass P@ssw0rd
	-cert sm2_tlcp_server_enc_cert.pem
	-in tool_cms_enveloped.pem
	-out tool_cms_decrypted.txt)
gmssl_expect_file_text(tool_cms_decrypted.txt "CMS command line test message")
