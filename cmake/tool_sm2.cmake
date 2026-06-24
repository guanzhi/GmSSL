execute_process(
	COMMAND bin/gmssl sm2keygen -pass P@ssw0rd -out sm2.pem -pubout sm2pub.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT EXISTS sm2.pem)
	message(FATAL_ERROR "generated file does not exist")
endif()
if(NOT EXISTS sm2pub.pem)
	message(FATAL_ERROR "generated file does not exist")
endif()

set(SECRET_MESSAGE "Secret message")
file(WRITE message.txt "${SECRET_MESSAGE}")

execute_process(
	COMMAND bin/gmssl sm2sign -key sm2.pem -pass P@ssw0rd -in message.txt -out sm2.sig
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()


execute_process(
	COMMAND bin/gmssl sm2verify -pubkey sm2pub.pem -in message.txt -sig sm2.sig
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
	OUTPUT_VARIABLE TEST_STDOUT
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
string(FIND "${TEST_STDOUT}" "success" VERIFY_SUCCESS)
if(VERIFY_SUCCESS EQUAL -1)
    message(FATAL_ERROR "verify failure")
endif()


execute_process(
	COMMAND bin/gmssl sm2encrypt -pubkey sm2pub.pem -in message.txt -out sm2.der
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
	OUTPUT_VARIABLE TEST_STDOUT
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND bin/gmssl sm2decrypt -key sm2.pem -pass P@ssw0rd -in sm2.der
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
	OUTPUT_VARIABLE TEST_STDOUT
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT "${TEST_STDOUT}" STREQUAL "${SECRET_MESSAGE}")
	message(FATAL_ERROR "stdout: ${TEST_STDOUT}")
endif()

execute_process(
	COMMAND bin/gmssl sm2keygen -pass P@ssw0rd -out sm2_peer.pem -pubout sm2_peer_pub.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND bin/gmssl sm2exch -stage init
		-exch_keyout sm2exch_alice_ra.pem -exch_pass P@ssw0rd
		-out sm2exch_ra.bin
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND bin/gmssl sm2exch -stage respond
		-key sm2_peer.pem -pass P@ssw0rd -id Bob
		-peer_pubkey sm2pub.pem -peer_id Alice -in sm2exch_ra.bin
		-exch_keyout sm2exch_bob_rb.pem -exch_pass P@ssw0rd
		-secret_state_out sm2exch_bob_secret_state.bin
		-out sm2exch_rb_sb.bin
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND bin/gmssl sm2exch -stage confirm
		-key sm2.pem -pass P@ssw0rd -id Alice
		-peer_pubkey sm2_peer_pub.pem -peer_id Bob
		-exch_key sm2exch_alice_ra.pem -exch_pass P@ssw0rd
		-in sm2exch_rb_sb.bin
		-keylen 48 -keyout sm2exch_alice_key.bin
		-secret_state_out sm2exch_alice_secret_state.bin
		-out sm2exch_sa.bin
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND bin/gmssl sm2exch -stage finish
		-key sm2_peer.pem -pass P@ssw0rd -id Bob
		-peer_pubkey sm2pub.pem -peer_id Alice
		-exch_key sm2exch_bob_rb.pem -exch_pass P@ssw0rd
		-secret_state sm2exch_bob_secret_state.bin
		-in sm2exch_sa.bin
		-keylen 48 -keyout sm2exch_bob_key.bin
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND ${CMAKE_COMMAND} -E compare_files sm2exch_alice_key.bin sm2exch_bob_key.bin
	RESULT_VARIABLE TEST_RESULT
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "SM2 key exchange output mismatch")
endif()

execute_process(
	COMMAND ${CMAKE_COMMAND} -E compare_files sm2exch_alice_secret_state.bin sm2exch_bob_secret_state.bin
	RESULT_VARIABLE TEST_RESULT
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "SM2 key exchange secret_state mismatch")
endif()

execute_process(
	COMMAND bin/gmssl sm2exch -stage init -bin
		-exch_keyout sm2exch_bin_alice_ra.pem -exch_pass P@ssw0rd
		-out sm2exch_bin_ra.bin
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND bin/gmssl sm2exch -stage respond -bin
		-key sm2_peer.pem -pass P@ssw0rd -id Bob
		-peer_pubkey sm2pub.pem -peer_id Alice -in sm2exch_bin_ra.bin
		-exch_keyout sm2exch_bin_bob_rb.pem -exch_pass P@ssw0rd
		-secret_state_out sm2exch_bin_bob_secret_state.bin
		-out sm2exch_bin_rb_sb.bin
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND bin/gmssl sm2exch -stage confirm -bin
		-key sm2.pem -pass P@ssw0rd -id Alice
		-peer_pubkey sm2_peer_pub.pem -peer_id Bob
		-exch_key sm2exch_bin_alice_ra.pem -exch_pass P@ssw0rd
		-in sm2exch_bin_rb_sb.bin
		-keylen 48 -keyout sm2exch_bin_alice_key.bin
		-secret_state_out sm2exch_bin_alice_secret_state.bin
		-out sm2exch_bin_sa.bin
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND bin/gmssl sm2exch -stage finish -bin
		-key sm2_peer.pem -pass P@ssw0rd -id Bob
		-peer_pubkey sm2pub.pem -peer_id Alice
		-exch_key sm2exch_bin_bob_rb.pem -exch_pass P@ssw0rd
		-secret_state sm2exch_bin_bob_secret_state.bin
		-in sm2exch_bin_sa.bin
		-keylen 48 -keyout sm2exch_bin_bob_key.bin
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND ${CMAKE_COMMAND} -E compare_files sm2exch_bin_alice_key.bin sm2exch_bin_bob_key.bin
	RESULT_VARIABLE TEST_RESULT
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "SM2 binary key exchange output mismatch")
endif()

execute_process(
	COMMAND bin/gmssl sm2exch -stage init
		-exch_keyout sm2exch_stdio_alice_ra.pem -exch_pass P@ssw0rd
	OUTPUT_FILE sm2exch_stdio_ra.hex
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND bin/gmssl sm2exch -stage respond
		-key sm2_peer.pem -pass P@ssw0rd -id Bob
		-peer_pubkey sm2pub.pem -peer_id Alice
		-exch_keyout sm2exch_stdio_bob_rb.pem -exch_pass P@ssw0rd
		-secret_state_out sm2exch_stdio_bob_secret_state.hex
	INPUT_FILE sm2exch_stdio_ra.hex
	OUTPUT_FILE sm2exch_stdio_rb_sb.hex
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND bin/gmssl sm2exch -stage confirm
		-key sm2.pem -pass P@ssw0rd -id Alice
		-peer_pubkey sm2_peer_pub.pem -peer_id Bob
		-exch_key sm2exch_stdio_alice_ra.pem -exch_pass P@ssw0rd
		-keylen 48 -keyout sm2exch_stdio_alice_key.hex
		-secret_state_out sm2exch_stdio_alice_secret_state.hex
	INPUT_FILE sm2exch_stdio_rb_sb.hex
	OUTPUT_FILE sm2exch_stdio_sa.hex
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND bin/gmssl sm2exch -stage finish
		-key sm2_peer.pem -pass P@ssw0rd -id Bob
		-peer_pubkey sm2pub.pem -peer_id Alice
		-exch_key sm2exch_stdio_bob_rb.pem -exch_pass P@ssw0rd
		-secret_state sm2exch_stdio_bob_secret_state.hex
		-keylen 48 -keyout sm2exch_stdio_bob_key.hex
	INPUT_FILE sm2exch_stdio_sa.hex
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND ${CMAKE_COMMAND} -E compare_files sm2exch_stdio_alice_key.hex sm2exch_stdio_bob_key.hex
	RESULT_VARIABLE TEST_RESULT
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "SM2 stdio key exchange output mismatch")
endif()

execute_process(
	COMMAND bin/gmssl sm2sign -key sm2.pem -pass P@ssw0rd -id Alice -in message.txt -out sm2_id.sig
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND bin/gmssl sm2verify -pubkey sm2pub.pem -id Alice -in message.txt -sig sm2_id.sig
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
	OUTPUT_VARIABLE TEST_STDOUT
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
string(FIND "${TEST_STDOUT}" "success" VERIFY_SUCCESS)
if(VERIFY_SUCCESS EQUAL -1)
    message(FATAL_ERROR "verify failure")
endif()
