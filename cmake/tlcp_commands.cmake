
if(NOT EXISTS rootcacert.pem)
	message(FATAL_ERROR "file does not exist")
endif()

if(NOT EXISTS tlcp_server_certs.pem)
	message(FATAL_ERROR "file does not exist")
endif()

if(NOT EXISTS tlcp_server_keys.pem)
	message(FATAL_ERROR "file does not exist")
endif()

set(TLCP_TEST_PORT 4431)
file(REMOVE "tlcp_client.log" "tlcp_server.log")

if(NOT WIN32)
	execute_process(
		COMMAND pkill -f "gmssl tlcp_server"
		OUTPUT_QUIET
		ERROR_QUIET
	)
endif()

if(WIN32)
	execute_process(
		COMMAND cmd /c "start /B bin\\gmssl tlcp_server -port ${TLCP_TEST_PORT} -cert tlcp_server_certs.pem -key tlcp_server_keys.pem -pass P@ssw0rd > tlcp_server.log 2>&1"
		RESULT_VARIABLE SERVER_RESULT
		TIMEOUT 5
	)
else()
	execute_process(
		COMMAND bash -c "nohup bin/gmssl tlcp_server -port ${TLCP_TEST_PORT} -cert tlcp_server_certs.pem -key tlcp_server_keys.pem -pass P@ssw0rd > tlcp_server.log 2>&1 &"
		RESULT_VARIABLE SERVER_RESULT
		TIMEOUT 5
	)
endif()
if(NOT ${SERVER_RESULT} EQUAL 0)
	message(FATAL_ERROR "server failed to start")
endif()

set(FOUND_INDEX -1)
foreach(i RANGE 1 15)
	if (WIN32)
		execute_process(
			COMMAND cmd /c "start /B bin\\gmssl tlcp_client -host 127.0.0.1 -port ${TLCP_TEST_PORT} -cacert rootcacert.pem -cipher_suite TLS_ECC_SM4_CBC_SM3 > tlcp_client.log 2>&1"
			RESULT_VARIABLE CLIENT_RESULT
			TIMEOUT 5
		)
	else()
		execute_process(
			COMMAND bash -c "bin/gmssl tlcp_client -host 127.0.0.1 -port ${TLCP_TEST_PORT} -cacert rootcacert.pem -cipher_suite TLS_ECC_SM4_CBC_SM3 < /dev/null > tlcp_client.log 2>&1 &"
			RESULT_VARIABLE CLIENT_RESULT
			TIMEOUT 5
		)
	endif()
	if(NOT ${CLIENT_RESULT} EQUAL 0)
		message(FATAL_ERROR "client failed to start")
	endif()
	execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 1)
	if(EXISTS "tlcp_client.log")
		file(READ "tlcp_client.log" CLIENT_LOG_CONTENT)
		string(FIND "${CLIENT_LOG_CONTENT}" "Connection established" FOUND_INDEX)
		if(NOT ${FOUND_INDEX} EQUAL -1)
			break()
		endif()
	endif()
endforeach()

if(NOT WIN32)
	execute_process(
		COMMAND pkill -f "gmssl tlcp_server"
		OUTPUT_QUIET
		ERROR_QUIET
	)
	execute_process(
		COMMAND pkill -f "gmssl tlcp_client"
		OUTPUT_QUIET
		ERROR_QUIET
	)
endif()

if(${FOUND_INDEX} EQUAL -1)
	if(EXISTS "tlcp_server.log")
		file(READ "tlcp_server.log" SERVER_LOG_CONTENT)
		message(STATUS "tlcp_server.log:\n${SERVER_LOG_CONTENT}")
	endif()
	if(EXISTS "tlcp_client.log")
		file(READ "tlcp_client.log" CLIENT_LOG_CONTENT)
		message(STATUS "tlcp_client.log:\n${CLIENT_LOG_CONTENT}")
	endif()
	message(FATAL_ERROR "Client did not establish connection with server.")
endif()
