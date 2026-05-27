
if(NOT EXISTS rootcacert.pem)
	message(FATAL_ERROR "file does not exist")
endif()

if(NOT EXISTS tls_server_certs.pem)
	message(FATAL_ERROR "file does not exist")
endif()

if(NOT EXISTS signkey.pem)
	message(FATAL_ERROR "file does not exist")
endif()

execute_process(
	COMMAND pkill -f "gmssl tls13_server"
	OUTPUT_QUIET
	ERROR_QUIET
)

execute_process(
	COMMAND bash -c "nohup bin/gmssl tls13_server -port 4443 -cert tls_server_certs.pem -key signkey.pem -pass P@ssw0rd -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 > tls13_server.log 2>&1 &"
	RESULT_VARIABLE SERVER_RESULT
	TIMEOUT 5
)
if(NOT ${SERVER_RESULT} EQUAL 0)
	message(FATAL_ERROR "server failed to start")
endif()

execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 2)

execute_process(
	COMMAND bash -c "bin/gmssl tls13_client -host localhost -port 4443 -cacert rootcacert.pem -cipher_suite TLS_SM4_GCM_SM3 -supported_group sm2p256v1 -sig_alg sm2sig_sm3 > tls13_client.log 2>&1"
	RESULT_VARIABLE CLIENT_RESULT
	TIMEOUT 5
)

execute_process(
	COMMAND pkill -f "gmssl tls13_server"
)

file(READ "tls13_client.log" CLIENT_LOG_CONTENT)
string(FIND "${CLIENT_LOG_CONTENT}" "connected" FOUND_INDEX)

if(${FOUND_INDEX} EQUAL -1)
	message(FATAL_ERROR "Client did not establish connection with server.")
endif()
