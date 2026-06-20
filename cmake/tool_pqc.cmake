include("${CMAKE_CURRENT_LIST_DIR}/tool_helpers.cmake")

file(WRITE tool_pqc_message.txt "PQC command line test message")

function(gmssl_signature_roundtrip name keygen sign verify)
	cmake_parse_arguments(ARG "" "" "KEYGEN_ARGS;SIGN_ARGS;VERIFY_ARGS" ${ARGN})
	gmssl_run(${keygen} ${ARG_KEYGEN_ARGS}
		-out "${name}_key.pem" -pubout "${name}_pub.pem")
	gmssl_run(${sign} -key "${name}_key.pem"
		-in tool_pqc_message.txt -out "${name}.sig" ${ARG_SIGN_ARGS})
	gmssl_run(${verify} -pubkey "${name}_pub.pem"
		-in tool_pqc_message.txt -sig "${name}.sig" ${ARG_VERIFY_ARGS})
endfunction()

if(ENABLE_LMS)
	gmssl_signature_roundtrip(tool_lms lmskeygen lmssign lmsverify
		KEYGEN_ARGS -lms_type LMS_SM3_M32_H5)
	gmssl_signature_roundtrip(tool_hss hsskeygen hsssign hssverify
		KEYGEN_ARGS -lms_types LMS_SM3_M32_H5:LMS_SM3_M32_H5)
endif()

if(ENABLE_XMSS)
	gmssl_signature_roundtrip(tool_xmss xmsskeygen xmsssign xmssverify
		KEYGEN_ARGS -xmss_type XMSS_SHA2_10_256)
	gmssl_signature_roundtrip(tool_xmssmt xmssmtkeygen xmssmtsign xmssmtverify
		KEYGEN_ARGS -xmssmt_type XMSSMT_SHA2_20_2_256)
endif()

if(ENABLE_SPHINCS)
	gmssl_signature_roundtrip(tool_sphincs sphincskeygen sphincssign sphincsverify)
endif()

if(ENABLE_KYBER)
	gmssl_run(kyberkeygen -out tool_kyber_key.pem -pubout tool_kyber_pub.pem)
	gmssl_run(kyberencap -pubkey tool_kyber_pub.pem
		-out tool_kyber_cipher.bin -outkey tool_kyber_secret.bin)
	gmssl_run(kyberdecap -key tool_kyber_key.pem
		-in tool_kyber_cipher.bin -out tool_kyber_dec_secret.bin)
	gmssl_files_equal(tool_kyber_secret.bin tool_kyber_dec_secret.bin)
endif()
