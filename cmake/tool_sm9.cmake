include("${CMAKE_CURRENT_LIST_DIR}/tool_helpers.cmake")

set(SM9_PASS P@ssw0rd)
set(SM9_USER_PASS 123456)
set(SM9_ID Alice)
set(SM9_TEXT "SM9 command line test message")

file(WRITE tool_sm9_message.txt "${SM9_TEXT}")

gmssl_run(sm9setup -alg sm9sign -pass ${SM9_PASS}
	-out tool_sm9_sign_msk.pem -pubout tool_sm9_sign_mpk.pem)
gmssl_run(sm9keygen -alg sm9sign
	-in tool_sm9_sign_msk.pem -inpass ${SM9_PASS}
	-id ${SM9_ID}
	-out tool_sm9_sign_key.pem -outpass ${SM9_USER_PASS})
gmssl_run(sm9sign -key tool_sm9_sign_key.pem -pass ${SM9_USER_PASS}
	-in tool_sm9_message.txt -out tool_sm9.sig)
gmssl_run(sm9verify -pubmaster tool_sm9_sign_mpk.pem -id ${SM9_ID}
	-in tool_sm9_message.txt -sig tool_sm9.sig)

gmssl_run(sm9setup -alg sm9encrypt -pass ${SM9_PASS}
	-out tool_sm9_enc_msk.pem -pubout tool_sm9_enc_mpk.pem)
gmssl_run(sm9keygen -alg sm9encrypt
	-in tool_sm9_enc_msk.pem -inpass ${SM9_PASS}
	-id ${SM9_ID}
	-out tool_sm9_enc_key.pem -outpass ${SM9_USER_PASS})
gmssl_run(sm9keygen -alg sm9keyagreement
	-in tool_sm9_enc_msk.pem -inpass ${SM9_PASS}
	-id Bob
	-out tool_sm9_bob_exch_key.pem -outpass ${SM9_USER_PASS})
gmssl_run(sm9encrypt -pubmaster tool_sm9_enc_mpk.pem -id ${SM9_ID}
	-in tool_sm9_message.txt -out tool_sm9_cipher.der)
gmssl_run(sm9decrypt -key tool_sm9_enc_key.pem -pass ${SM9_USER_PASS} -id ${SM9_ID}
	-in tool_sm9_cipher.der -out tool_sm9_plain.txt)
gmssl_expect_file_text(tool_sm9_plain.txt "${SM9_TEXT}")

gmssl_run(sm9keygen -alg sm9keyagreement
	-in tool_sm9_enc_msk.pem -inpass ${SM9_PASS}
	-id ${SM9_ID}
	-out tool_sm9_alice_exch_key.pem -outpass ${SM9_USER_PASS})
gmssl_run(sm9exch -stage init
	-pubmaster tool_sm9_enc_mpk.pem -peer_id Bob
	-exch_keyout tool_sm9_alice_ra.pem -out tool_sm9_ra.bin)
gmssl_run(sm9exch -stage respond
	-pubmaster tool_sm9_enc_mpk.pem
	-key tool_sm9_bob_exch_key.pem -pass ${SM9_USER_PASS} -id Bob
	-peer_id ${SM9_ID} -in tool_sm9_ra.bin
	-exch_keyout tool_sm9_bob_rb.pem -out tool_sm9_rb_sb.bin)
gmssl_run(sm9exch -stage confirm
	-pubmaster tool_sm9_enc_mpk.pem
	-key tool_sm9_alice_exch_key.pem -pass ${SM9_USER_PASS} -id ${SM9_ID}
	-peer_id Bob -exch_key tool_sm9_alice_ra.pem
	-in tool_sm9_rb_sb.bin
	-keylen 48 -keyout tool_sm9_alice_shared_key.bin
	-out tool_sm9_sa.bin)
gmssl_run(sm9exch -stage finish
	-pubmaster tool_sm9_enc_mpk.pem
	-key tool_sm9_bob_exch_key.pem -pass ${SM9_USER_PASS} -id Bob
	-peer_id ${SM9_ID}
	-exch_key tool_sm9_bob_rb.pem
	-in tool_sm9_sa.bin
	-keylen 48 -keyout tool_sm9_bob_shared_key.bin)
gmssl_files_equal(tool_sm9_alice_shared_key.bin tool_sm9_bob_shared_key.bin)

gmssl_run(sm9exch -stage init -bin
	-pubmaster tool_sm9_enc_mpk.pem -peer_id Bob
	-exch_keyout tool_sm9_bin_alice_ra.pem -out tool_sm9_bin_ra.bin)
gmssl_run(sm9exch -stage respond -bin
	-pubmaster tool_sm9_enc_mpk.pem
	-key tool_sm9_bob_exch_key.pem -pass ${SM9_USER_PASS} -id Bob
	-peer_id ${SM9_ID} -in tool_sm9_bin_ra.bin
	-exch_keyout tool_sm9_bin_bob_rb.pem -out tool_sm9_bin_rb_sb.bin)
gmssl_run(sm9exch -stage confirm -bin
	-pubmaster tool_sm9_enc_mpk.pem
	-key tool_sm9_alice_exch_key.pem -pass ${SM9_USER_PASS} -id ${SM9_ID}
	-peer_id Bob -exch_key tool_sm9_bin_alice_ra.pem
	-in tool_sm9_bin_rb_sb.bin
	-keylen 48 -keyout tool_sm9_bin_alice_shared_key.bin
	-out tool_sm9_bin_sa.bin)
gmssl_run(sm9exch -stage finish -bin
	-pubmaster tool_sm9_enc_mpk.pem
	-key tool_sm9_bob_exch_key.pem -pass ${SM9_USER_PASS} -id Bob
	-peer_id ${SM9_ID}
	-exch_key tool_sm9_bin_bob_rb.pem
	-in tool_sm9_bin_sa.bin
	-keylen 48 -keyout tool_sm9_bin_bob_shared_key.bin)
gmssl_files_equal(tool_sm9_bin_alice_shared_key.bin tool_sm9_bin_bob_shared_key.bin)

execute_process(
	COMMAND ${GMSSL_BIN} sm9exch -stage init
		-pubmaster tool_sm9_enc_mpk.pem -peer_id Bob
		-exch_keyout tool_sm9_stdio_alice_ra.pem
	OUTPUT_FILE tool_sm9_stdio_ra.hex
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT TEST_RESULT EQUAL 0)
	message(FATAL_ERROR "command failed: ${GMSSL_BIN} sm9exch -stage init\nstderr: ${TEST_STDERR}")
endif()
execute_process(
	COMMAND ${GMSSL_BIN} sm9exch -stage respond
		-pubmaster tool_sm9_enc_mpk.pem
		-key tool_sm9_bob_exch_key.pem -pass ${SM9_USER_PASS} -id Bob
		-peer_id ${SM9_ID}
		-exch_keyout tool_sm9_stdio_bob_rb.pem
	INPUT_FILE tool_sm9_stdio_ra.hex
	OUTPUT_FILE tool_sm9_stdio_rb_sb.hex
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT TEST_RESULT EQUAL 0)
	message(FATAL_ERROR "command failed: ${GMSSL_BIN} sm9exch -stage respond\nstderr: ${TEST_STDERR}")
endif()
execute_process(
	COMMAND ${GMSSL_BIN} sm9exch -stage confirm
		-pubmaster tool_sm9_enc_mpk.pem
		-key tool_sm9_alice_exch_key.pem -pass ${SM9_USER_PASS} -id ${SM9_ID}
		-peer_id Bob -exch_key tool_sm9_stdio_alice_ra.pem
		-keylen 48 -keyout tool_sm9_stdio_alice_shared_key.hex
	INPUT_FILE tool_sm9_stdio_rb_sb.hex
	OUTPUT_FILE tool_sm9_stdio_sa.hex
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT TEST_RESULT EQUAL 0)
	message(FATAL_ERROR "command failed: ${GMSSL_BIN} sm9exch -stage confirm\nstderr: ${TEST_STDERR}")
endif()
execute_process(
	COMMAND ${GMSSL_BIN} sm9exch -stage finish
		-pubmaster tool_sm9_enc_mpk.pem
		-key tool_sm9_bob_exch_key.pem -pass ${SM9_USER_PASS} -id Bob
		-peer_id ${SM9_ID}
		-exch_key tool_sm9_stdio_bob_rb.pem
		-keylen 48 -keyout tool_sm9_stdio_bob_shared_key.hex
	INPUT_FILE tool_sm9_stdio_sa.hex
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT TEST_RESULT EQUAL 0)
	message(FATAL_ERROR "command failed: ${GMSSL_BIN} sm9exch -stage finish\nstderr: ${TEST_STDERR}")
endif()
gmssl_files_equal(tool_sm9_stdio_alice_shared_key.hex tool_sm9_stdio_bob_shared_key.hex)
