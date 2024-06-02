
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

if(WIN32)
	execute_process(
		COMMAND cmd /c "start /B bin\\gmssl tlcp_server -port 4433 -cert tlcp_server_certs.pem -key signkey.pem -pass P@ssw0rd -ex_key enckey.pem -ex_pass P@ssw0rd > tlcp_server.log 2>&1"
		RESULT_VARIABLE SERVER_RESULT
		TIMEOUT 5
	)
else()
	execute_process(
		COMMAND bash -c "sudo nohup bin/gmssl tlcp_server -port 4433 -cert tlcp_server_certs.pem -key signkey.pem -pass P@ssw0rd -ex_key enckey.pem -ex_pass P@ssw0rd > tlcp_server.log 2>&1 &"
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
		COMMAND cmd /c "start /B bin\\gmssl tlcp_client -host localhost -port 4433 -cacert rootcacert.pem > tlcp_client.log 2>&1"
		RESULT_VARIABLE CLIENT_RESULT
		TIMEOUT 5
	)
else()
	execute_process(
		COMMAND bash -c "bin/gmssl tlcp_client -host localhost -port 4433 -cacert rootcacert.pem > tlcp_client.log 2>&1"
		RESULT_VARIABLE CLIENT_RESULT
		TIMEOUT 5
	)
endif()

file(READ "tlcp_client.log" CLIENT_LOG_CONTENT)
string(FIND "${CLIENT_LOG_CONTENT}" "Connection established" FOUND_INDEX)

if(${FOUND_INDEX} EQUAL -1)
	message(FATAL_ERROR "Client did not establish connection with server.")
endif()

execute_process(
	COMMAND sudo pkill -f "gmssl"
)

