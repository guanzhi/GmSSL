
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

execute_process(
	COMMAND bash -c "sudo nohup bin/gmssl tls12_server -port 4333 -cert tls_server_certs.pem -key signkey.pem -pass P@ssw0rd > tls12_server.log 2>&1 &"
	RESULT_VARIABLE SERVER_RESULT
	TIMEOUT 5
)
if(NOT ${SERVER_RESULT} EQUAL 0)
	message(FATAL_ERROR "server failed to start")
endif()

execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 2)

execute_process(
	COMMAND bash -c "bin/gmssl tls12_client -host localhost -port 4333 -cacert rootcacert.pem > tls12_client.log 2>&1"
	RESULT_VARIABLE CLIENT_RESULT
	TIMEOUT 5
)

file(READ "tls12_client.log" CLIENT_LOG_CONTENT)
string(FIND "${CLIENT_LOG_CONTENT}" "Connection established" FOUND_INDEX)

if(${FOUND_INDEX} EQUAL -1)
	message(FATAL_ERROR "Client did not establish connection with server.")
endif()

execute_process(
	COMMAND sudo pkill -f "gmssl"
)

