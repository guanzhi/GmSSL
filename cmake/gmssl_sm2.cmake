execute_process(
	COMMAND gmssl sm2keygen -pass P@ssw0rd -out sm2.pem -pubout sm2pub.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
	OUTPUT_VARIABLE TEST_OUTPUT
)

if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

if(NOT EXISTS sm2.pem)
    message(FATAL_ERROR "Generated file does not exist")
endif()

if(NOT EXISTS sm2pub.pem)
    message(FATAL_ERROR "Generated file does not exist")
endif()

# sign

execute_process(
	COMMAND bash -c "echo -n 'message to be signed' | gmssl sm2sign -key sm2.pem -pass P@ssw0rd -out sm2.sig"
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
	OUTPUT_VARIABLE TEST_OUTPUT
)

if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

# verify

execute_process(
	COMMAND bash -c "echo -n 'message to be signed' | gmssl sm2verify -pubkey sm2pub.pem -sig sm2.sig"
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
	OUTPUT_VARIABLE TEST_OUTPUT
)

if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

#encrypt

execute_process(
	COMMAND bash -c "echo 'Secret message' | gmssl sm2encrypt -pubkey sm2pub.pem -out sm2.der"
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
	OUTPUT_VARIABLE TEST_OUTPUT
)

if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

# decrypt

execute_process(
	COMMAND bash -c "echo 'Secret message' | gmssl sm2encrypt -pubkey sm2pub.pem -out sm2.der"
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
	OUTPUT_VARIABLE TEST_OUTPUT
)

if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()


if(NOT ${TEST_OUTPUT} STREQUAL "Secret message")
	message(FATAL_ERROR "stdout: ${TEST_OUTPUT}")
endif()

