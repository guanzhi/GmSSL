
execute_process(
	COMMAND bin/gmssl sm2keygen -pass P@ssw0rd -out rootcakey.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT EXISTS rootcakey.pem)
	message(FATAL_ERROR "generated file does not exist")
endif()

execute_process(
	COMMAND bin/gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 -key rootcakey.pem -pass P@ssw0rd -out rootcacert.pem -key_usage keyCertSign -key_usage cRLSign -ca
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT EXISTS rootcacert.pem)
	message(FATAL_ERROR "generated file does not exist")
endif()
file(READ rootcacert.pem FILE_CONTENT)
if (NOT FILE_CONTENT MATCHES "^-----BEGIN CERTIFICATE-----")
	message(FATAL_ERROR "generate file error")
endif()

execute_process(
	COMMAND bin/gmssl sm2keygen -pass P@ssw0rd -out cakey.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT EXISTS cakey.pem)
	message(FATAL_ERROR "generated file does not exist")
endif()

execute_process(
	COMMAND bin/gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN "Sub CA" -key cakey.pem -pass P@ssw0rd -out careq.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT EXISTS careq.pem)
    message(FATAL_ERROR "generated file does not exist")
endif()
file(READ careq.pem FILE_CONTENT)
if (NOT FILE_CONTENT MATCHES "^-----BEGIN CERTIFICATE REQUEST-----")
	message(FATAL_ERROR "generate file error")
endif()

execute_process(
	COMMAND bin/gmssl reqsign -in careq.pem -days 365 -key_usage keyCertSign -path_len_constraint 0 -cacert rootcacert.pem -key rootcakey.pem -pass P@ssw0rd -out cacert.pem -ca
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT EXISTS cacert.pem)
	message(FATAL_ERROR "generated file does not exist")
endif()

execute_process(
	COMMAND bin/gmssl sm2keygen -pass P@ssw0rd -out signkey.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT EXISTS signkey.pem)
	message(FATAL_ERROR "generated file does not exist")
endif()

execute_process(
	COMMAND bin/gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key signkey.pem -pass P@ssw0rd -out signreq.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT EXISTS signreq.pem)
    message(FATAL_ERROR "generated file does not exist")
endif()

execute_process(
	COMMAND bin/gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass P@ssw0rd -out signcert.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT EXISTS signcert.pem)
	message(FATAL_ERROR "generated file does not exist")
endif()

execute_process(
	COMMAND bin/gmssl sm2keygen -pass P@ssw0rd -out enckey.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT EXISTS enckey.pem)
    message(FATAL_ERROR "generated file does not exist")
endif()

execute_process(
	COMMAND bin/gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key enckey.pem -pass P@ssw0rd -out encreq.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT EXISTS encreq.pem)
	message(FATAL_ERROR "generated file does not exist")
endif()

execute_process(
	COMMAND bin/gmssl reqsign -in encreq.pem -days 365 -key_usage keyEncipherment -cacert cacert.pem -key cakey.pem -pass P@ssw0rd -out enccert.pem
	RESULT_VARIABLE TEST_RESULT
	ERROR_VARIABLE TEST_STDERR
)
if(NOT ${TEST_RESULT} EQUAL 0)
	message(FATAL_ERROR "stderr: ${TEST_STDERR}")
endif()
if(NOT EXISTS enccert.pem)
	message(FATAL_ERROR "generated file does not exist")
endif()

file(WRITE tlcp_server_certs.pem "")
file(READ signcert.pem CERT_CONTENT)
file(APPEND tlcp_server_certs.pem "${CERT_CONTENT}")
file(READ enccert.pem CERT_CONTENT)
file(APPEND tlcp_server_certs.pem "${CERT_CONTENT}")
file(READ cacert.pem CERT_CONTENT)
file(APPEND tlcp_server_certs.pem "${CERT_CONTENT}")

file(WRITE tls_server_certs.pem "")
file(READ signcert.pem CERT_CONTENT)
file(APPEND tls_server_certs.pem "${CERT_CONTENT}")
file(READ cacert.pem CERT_CONTENT)
file(APPEND tls_server_certs.pem "${CERT_CONTENT}")

