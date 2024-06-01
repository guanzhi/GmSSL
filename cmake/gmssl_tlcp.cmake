
# tlcp_server [-port num] -cert file -key file [-pass str] -ex_key file [-ex_pass str] [-cacert file]
execute_process(
    COMMAND bash -c "sudo nohup gmssl tlcp_server -port 4433 -cert double_certs.pem -key signkey.pem -pass P@ssw0rd -ex_key enckey.pem -ex_pass P@ssw0rd > server_output.log 2>&1 &"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    RESULT_VARIABLE SERVER_RESULT
    TIMEOUT 5
    COMMAND_ECHO STDOUT
    OUTPUT_VARIABLE SERVER_OUTPUT
    ERROR_VARIABLE SERVER_ERROR
)
message(STATUS "Server start output: ${SERVER_OUTPUT}")
message(STATUS "Server start error: ${SERVER_ERROR}")

if(NOT ${SERVER_RESULT} EQUAL 0)
    message(FATAL_ERROR "Server failed to start with result: ${SERVER_RESULT}")
endif()

execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 2)




execute_process(
    COMMAND bash -c "gmssl tlcp_client -host localhost -port 4433 -cacert rootcacert.pem 2>&1 | tee client_output.log"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    OUTPUT_VARIABLE CLIENT_OUTPUT
    ERROR_VARIABLE CLIENT_ERROR
    RESULT_VARIABLE CLIENT_RESULT
    TIMEOUT 5
    COMMAND_ECHO STDOUT
)

message(STATUS "Client connection output: ${CLIENT_OUTPUT}")
message(STATUS "Client connection error: ${CLIENT_ERROR}")

file(READ "${CMAKE_BINARY_DIR}/client_output.log" CLIENT_LOG_CONTENT)
string(FIND "${CLIENT_LOG_CONTENT}" "Connection established" FOUND_INDEX)

if(${FOUND_INDEX} EQUAL -1)
    message(FATAL_ERROR "Client did not establish connection with server.")
else()
    message(STATUS "Client successfully established connection with server.")
endif()

execute_process(
    COMMAND sudo pkill -f "${TOOL_COMMAND} tlcp_server"
)

