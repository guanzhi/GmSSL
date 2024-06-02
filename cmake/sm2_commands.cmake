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

