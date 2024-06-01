

execute_process(
	COMMAND gmssl sm2keygen -pass P@ssw0rd -out rootcakey.pem
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



execute_process(
	COMMAND gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 -key rootcakey.pem -pass P@ssw0rd -out rootcacert.pem -key_usage keyCertSign -key_usage cRLSign -ca
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
	OUTPUT_VARIABLE TEST_OUTPUT
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()



execute_process(
	COMMAND gmssl sm2keygen -pass P@ssw0rd -out cakey.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
	OUTPUT_VARIABLE TEST_OUTPUT
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()


execute_process(
	COMMAND gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN "Sub CA" -key cakey.pem -pass P@ssw0rd -out careq.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()



execute_process(
	COMMAND gmssl reqsign -in careq.pem -days 365 -key_usage keyCertSign -path_len_constraint 0 -cacert rootcacert.pem -key rootcakey.pem -pass P@ssw0rd -out cacert.pem -ca
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()


# gmssl sm2keygen -pass P@ssw0rd -out signkey.pem
# gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key signkey.pem -pass P@ssw0rd -out signreq.pem
# gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass P@ssw0rd -out signcert.pem

execute_process(
	COMMAND gmssl sm2keygen -pass P@ssw0rd -out signkey.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key signkey.pem -pass P@ssw0rd -out signreq.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass P@ssw0rd -out signcert.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()


# gmssl sm2keygen -pass P@ssw0rd -out enckey.pem
# gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key enckey.pem -pass P@ssw0rd -out encreq.pem
# gmssl reqsign -in encreq.pem -days 365 -key_usage keyEncipherment -cacert cacert.pem -key cakey.pem -pass P@ssw0rd -out enccert.pem


execute_process(
	COMMAND gmssl sm2keygen -pass P@ssw0rd -out enckey.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key enckey.pem -pass P@ssw0rd -out encreq.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()

execute_process(
	COMMAND gmssl reqsign -in encreq.pem -days 365 -key_usage keyEncipherment -cacert cacert.pem -key cakey.pem -pass P@ssw0rd -out enccert.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()



file(WRITE double_certs.pem "")
file(READ signcert.pem CERT_CONTENT)
file(APPEND double_certs.pem "${CERT_CONTENT}")
file(READ enccert.pem CERT_CONTENT)
file(APPEND double_certs.pem "${CERT_CONTENT}")
file(READ cacert.pem CERT_CONTENT)
file(APPEND double_certs.pem "${CERT_CONTENT}")





