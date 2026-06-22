include("${CMAKE_CURRENT_LIST_DIR}/tool_helpers.cmake")

set(SM4_KEY 0123456789abcdeffedcba9876543210)
set(SM4_IV 00000000000000000000000000000000)
set(SM4_HMAC_KEY 0123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210)
set(SM4_XTS_KEY 0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff)
set(SM4_FF1_KEY 2b7e151628aed2a6abf7158809cf4f3c)
set(SM4_TEXT "0123456789abcdef0123456789abcdef")

function(gmssl_symmetric_roundtrip name)
	file(WRITE "${name}.plain" "${SM4_TEXT}")
	gmssl_run(${ARGN} -encrypt -in "${name}.plain" -out "${name}.cipher")
	gmssl_run(${ARGN} -decrypt -in "${name}.cipher" -out "${name}.decrypt")
	gmssl_files_equal("${name}.plain" "${name}.decrypt")
endfunction()

file(WRITE tool_sm4_cbc_kat.plain "0123456789abcdef")
gmssl_run(sm4_cbc -encrypt -key ${SM4_KEY} -iv ${SM4_IV}
	-in tool_sm4_cbc_kat.plain -out tool_sm4_cbc_kat.cipher)
gmssl_expect_file_hex(tool_sm4_cbc_kat.cipher
	"e6887b77dbabb572ffa07fed7548b192ceaace11f2b90b94c2b7a4d9382e471e")
gmssl_run(sm4_cbc -decrypt -key ${SM4_KEY} -iv ${SM4_IV}
	-in tool_sm4_cbc_kat.cipher -out tool_sm4_cbc_kat.decrypt)
gmssl_files_equal(tool_sm4_cbc_kat.plain tool_sm4_cbc_kat.decrypt)

gmssl_symmetric_roundtrip(tool_sm4_cbc sm4_cbc -key ${SM4_KEY} -iv ${SM4_IV})
gmssl_symmetric_roundtrip(tool_sm4_ctr sm4_ctr -key ${SM4_KEY} -iv ${SM4_IV})
gmssl_symmetric_roundtrip(tool_sm4_gcm sm4_gcm -key ${SM4_KEY} -iv 000000000000000000000000 -aad_hex 001122 -taglen 16)
gmssl_symmetric_roundtrip(tool_sm4_cbc_sm3_hmac sm4_cbc_sm3_hmac -key ${SM4_HMAC_KEY} -iv ${SM4_IV} -aad_hex 001122)
gmssl_symmetric_roundtrip(tool_sm4_ctr_sm3_hmac sm4_ctr_sm3_hmac -key ${SM4_HMAC_KEY} -iv ${SM4_IV} -aad_hex 001122)

if(ENABLE_SM4_ECB)
	gmssl_symmetric_roundtrip(tool_sm4_ecb sm4_ecb -key ${SM4_KEY})
endif()
if(ENABLE_SM4_CFB)
	gmssl_symmetric_roundtrip(tool_sm4_cfb sm4_cfb -sbytes 16 -key ${SM4_KEY} -iv ${SM4_IV})
endif()
if(ENABLE_SM4_OFB)
	gmssl_symmetric_roundtrip(tool_sm4_ofb sm4_ofb -key ${SM4_KEY} -iv ${SM4_IV})
endif()
if(ENABLE_SM4_CCM)
	gmssl_symmetric_roundtrip(tool_sm4_ccm sm4_ccm -key ${SM4_KEY} -iv 000000000000000000000000 -aad_hex 001122 -taglen 16)
endif()
if(ENABLE_SM4_XTS)
	file(WRITE tool_sm4_xts.plain "0123456789abcdef0123456789abcdef")
	gmssl_run(sm4_xts -encrypt -key ${SM4_XTS_KEY} -iv ${SM4_IV} -data_unit_size 32
		-in tool_sm4_xts.plain -out tool_sm4_xts.cipher)
	gmssl_run(sm4_xts -decrypt -key ${SM4_XTS_KEY} -iv ${SM4_IV} -data_unit_size 32
		-in tool_sm4_xts.cipher -out tool_sm4_xts.decrypt)
	gmssl_files_equal(tool_sm4_xts.plain tool_sm4_xts.decrypt)
endif()
if(ENABLE_SM4_FF1)
	gmssl_expect_stdout("2326982895499381\n"
		sm4_ff1 -encrypt -key ${SM4_FF1_KEY} -tweak 39383736353433323130 -digits 6226090102675688)
	gmssl_expect_stdout("6226090102675688\n"
		sm4_ff1 -decrypt -key ${SM4_FF1_KEY} -tweak 39383736353433323130 -digits 2326982895499381)
endif()
if(ENABLE_SM4_CBC_MAC)
	gmssl_expect_stdout("9054fccff72871fdad5202c821dbea05\n"
		sm4_cbc_mac -key ${SM4_KEY} -in_str abc)
	gmssl_run(sm4_cbc_mac -key ${SM4_KEY} -bin -in_str abc -out tool_sm4_cbc_mac.bin)
	gmssl_expect_file_hex(tool_sm4_cbc_mac.bin "9054fccff72871fdad5202c821dbea05")
endif()
