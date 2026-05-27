
if(NOT EXISTS rootcacert.pem)
	message(FATAL_ERROR "file does not exist")
endif()

if(NOT EXISTS tlcp_server_certs.pem)
	message(FATAL_ERROR "file does not exist")
endif()

if(NOT EXISTS signkey.pem)
	message(FATAL_ERROR "file does not exist")
endif()

if(NOT EXISTS enckey.pem)
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
		COMMAND cmd /c "start /B bin\\gmssl tlcp_server -port ${TLCP_TEST_PORT} -cert tlcp_server_certs.pem -key signkey.pem -pass P@ssw0rd -ex_key enckey.pem -ex_pass P@ssw0rd > tlcp_server.log 2>&1"
		RESULT_VARIABLE SERVER_RESULT
		TIMEOUT 5
	)
else()
	execute_process(
		COMMAND bash -c "nohup bin/gmssl tlcp_server -port ${TLCP_TEST_PORT} -cert tlcp_server_certs.pem -key signkey.pem -pass P@ssw0rd -ex_key enckey.pem -ex_pass P@ssw0rd > tlcp_server.log 2>&1 &"
		RESULT_VARIABLE SERVER_RESULT
		TIMEOUT 5
	)
endif()
if(NOT ${SERVER_RESULT} EQUAL 0)
	message(FATAL_ERROR "server failed to start")
endif()

execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 2)


if (WIN32)
	execute_process(
		COMMAND cmd /c "start /B bin\\gmssl tlcp_client -host localhost -port ${TLCP_TEST_PORT} -cacert rootcacert.pem > tlcp_client.log 2>&1"
		RESULT_VARIABLE CLIENT_RESULT
		TIMEOUT 5
	)
else()
	execute_process(
		COMMAND bash -c "bin/gmssl tlcp_client -host localhost -port ${TLCP_TEST_PORT} -cacert rootcacert.pem < /dev/null > tlcp_client.log 2>&1 &"
		RESULT_VARIABLE CLIENT_RESULT
		TIMEOUT 5
	)
endif()

set(FOUND_INDEX -1)
foreach(i RANGE 1 15)
	if(EXISTS "tlcp_client.log")
		file(READ "tlcp_client.log" CLIENT_LOG_CONTENT)
		string(FIND "${CLIENT_LOG_CONTENT}" "Connection established" FOUND_INDEX)
		if(NOT ${FOUND_INDEX} EQUAL -1)
			break()
		endif()
	endif()
	execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 1)
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
	message(FATAL_ERROR "Client did not establish connection with server.")
endif()
