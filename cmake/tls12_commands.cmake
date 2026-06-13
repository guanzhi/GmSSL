
if(NOT EXISTS rootcacert.pem)
	message(FATAL_ERROR "file does not exist")
endif()

if(NOT EXISTS tls_server_certs.pem)
	message(FATAL_ERROR "file does not exist")
endif()

if(NOT EXISTS signkey.pem)
	message(FATAL_ERROR "file does not exist")
endif()

if(NOT EXISTS enckey.pem)
	message(FATAL_ERROR "file does not exist")
endif()

set(TLS12_TEST_PORT 4432)
file(REMOVE "tls12_client.log" "tls12_server.log")

execute_process(
	COMMAND pkill -f "gmssl tls12_server"
	OUTPUT_QUIET
	ERROR_QUIET
)

execute_process(
	COMMAND bash -c "nohup bin/gmssl tls12_server -port ${TLS12_TEST_PORT} -cert tls_server_certs.pem -key signkey.pem -pass P@ssw0rd -cipher_suite TLS_ECDHE_SM4_CBC_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 > tls12_server.log 2>&1 &"
	RESULT_VARIABLE SERVER_RESULT
	TIMEOUT 5
)
if(NOT ${SERVER_RESULT} EQUAL 0)
	message(FATAL_ERROR "server failed to start")
endif()

execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 2)

execute_process(
	COMMAND bash -c "bin/gmssl tls12_client -host localhost -port ${TLS12_TEST_PORT} -cacert rootcacert.pem -cipher_suite TLS_ECDHE_SM4_CBC_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 < /dev/null > tls12_client.log 2>&1 &"
	RESULT_VARIABLE CLIENT_RESULT
	TIMEOUT 5
)

set(FOUND_INDEX -1)
foreach(i RANGE 1 15)
	if(EXISTS "tls12_client.log")
		file(READ "tls12_client.log" CLIENT_LOG_CONTENT)
		string(FIND "${CLIENT_LOG_CONTENT}" "Connection established" FOUND_INDEX)
		if(NOT ${FOUND_INDEX} EQUAL -1)
			break()
		endif()
	endif()
	execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 1)
endforeach()

execute_process(
	COMMAND pkill -f "gmssl tls12_server"
	OUTPUT_QUIET
	ERROR_QUIET
)
execute_process(
	COMMAND pkill -f "gmssl tls12_client"
	OUTPUT_QUIET
	ERROR_QUIET
)

if(${FOUND_INDEX} EQUAL -1)
	message(FATAL_ERROR "Client did not establish connection with server.")
endif()
