function(gmssl_require_file file)
	if(NOT EXISTS "${file}")
		message(FATAL_ERROR "required file does not exist: ${file}")
	endif()
endfunction()

function(gmssl_run_command_interop_test)
	if(POLICY CMP0053)
		cmake_policy(PUSH)
		cmake_policy(SET CMP0053 NEW)
	endif()

	set(one_value_args TEST_NAME PORT SERVER_COMMAND CLIENT_COMMAND EXPECT_CLIENT_LOG EXPECT_SERVER_LOG)
	cmake_parse_arguments(TEST "" "${one_value_args}" "" ${ARGN})

	if(NOT TEST_TEST_NAME)
		message(FATAL_ERROR "TEST_NAME is required")
	endif()
	if(NOT TEST_PORT)
		message(FATAL_ERROR "PORT is required")
	endif()
	if(NOT TEST_SERVER_COMMAND)
		message(FATAL_ERROR "SERVER_COMMAND is required")
	endif()
	if(NOT TEST_CLIENT_COMMAND)
		message(FATAL_ERROR "CLIENT_COMMAND is required")
	endif()

	set(SERVER_LOG "${TEST_TEST_NAME}_server.log")
	set(CLIENT_LOG "${TEST_TEST_NAME}_client.log")
	set(SERVER_PID_FILE "${TEST_TEST_NAME}_server.pid")

	file(REMOVE "${SERVER_LOG}" "${CLIENT_LOG}" "${SERVER_PID_FILE}")

	execute_process(
		COMMAND bash -c "nohup ${TEST_SERVER_COMMAND} > ${SERVER_LOG} 2>&1 & echo $! > ${SERVER_PID_FILE}"
		RESULT_VARIABLE SERVER_RESULT
		TIMEOUT 5
	)
	if(NOT ${SERVER_RESULT} EQUAL 0)
		message(FATAL_ERROR "server failed to start")
	endif()

	execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 1)

	execute_process(
		COMMAND bash -c "${TEST_CLIENT_COMMAND} > ${CLIENT_LOG} 2>&1"
		RESULT_VARIABLE CLIENT_RESULT
		TIMEOUT 30
	)

	execute_process(
		COMMAND bash -c "if test -f ${SERVER_PID_FILE}; then kill $(cat ${SERVER_PID_FILE}) 2>/dev/null || true; fi"
		OUTPUT_QUIET
		ERROR_QUIET
	)
	execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 1)

	set(SERVER_LOG_CONTENT "")
	set(CLIENT_LOG_CONTENT "")
	if(EXISTS "${SERVER_LOG}")
		file(READ "${SERVER_LOG}" SERVER_LOG_CONTENT)
	endif()
	if(EXISTS "${CLIENT_LOG}")
		file(READ "${CLIENT_LOG}" CLIENT_LOG_CONTENT)
	endif()

	if(NOT ${CLIENT_RESULT} EQUAL 0)
		message(STATUS "${SERVER_LOG}:\n${SERVER_LOG_CONTENT}")
		message(STATUS "${CLIENT_LOG}:\n${CLIENT_LOG_CONTENT}")
		message(FATAL_ERROR "client failed with result ${CLIENT_RESULT}")
	endif()

	if(TEST_EXPECT_CLIENT_LOG)
		string(FIND "${CLIENT_LOG_CONTENT}" "${TEST_EXPECT_CLIENT_LOG}" FOUND_INDEX)
		if(${FOUND_INDEX} EQUAL -1)
			message(STATUS "${CLIENT_LOG}:\n${CLIENT_LOG_CONTENT}")
			message(FATAL_ERROR "client log does not contain expected text: ${TEST_EXPECT_CLIENT_LOG}")
		endif()
	endif()

	if(TEST_EXPECT_SERVER_LOG)
		string(FIND "${SERVER_LOG_CONTENT}" "${TEST_EXPECT_SERVER_LOG}" FOUND_INDEX)
		if(${FOUND_INDEX} EQUAL -1)
			message(STATUS "${SERVER_LOG}:\n${SERVER_LOG_CONTENT}")
			message(FATAL_ERROR "server log does not contain expected text: ${TEST_EXPECT_SERVER_LOG}")
		endif()
	endif()

	if(POLICY CMP0053)
		cmake_policy(POP)
	endif()
endfunction()

function(gmssl_run_tls_command_test)
	if(POLICY CMP0053)
		cmake_policy(PUSH)
		cmake_policy(SET CMP0053 NEW)
	endif()

	set(one_value_args TEST_NAME PORT EXPECT_CLIENT_LOG EXPECT_SERVER_LOG)
	set(multi_value_args SERVER_ARGS CLIENT_ARGS)
	cmake_parse_arguments(TEST "" "${one_value_args}" "${multi_value_args}" ${ARGN})

	if(NOT TEST_TEST_NAME)
		message(FATAL_ERROR "TEST_NAME is required")
	endif()
	if(NOT TEST_PORT)
		message(FATAL_ERROR "PORT is required")
	endif()
	if(NOT TEST_SERVER_ARGS)
		message(FATAL_ERROR "SERVER_ARGS is required")
	endif()
	if(NOT TEST_CLIENT_ARGS)
		message(FATAL_ERROR "CLIENT_ARGS is required")
	endif()

	list(GET TEST_SERVER_ARGS 0 SERVER_TOOL)
	set(SERVER_LOG "${TEST_TEST_NAME}_server.log")
	set(CLIENT_LOG "${TEST_TEST_NAME}_client.log")
	set(SERVER_PID_FILE "${TEST_TEST_NAME}_server.pid")

	file(REMOVE "${SERVER_LOG}" "${CLIENT_LOG}" "${SERVER_PID_FILE}")
	file(WRITE "${TEST_TEST_NAME}_message.txt" "GmSSL ${TEST_TEST_NAME} command test\n")
	file(WRITE "${TEST_TEST_NAME}_early_data.txt" "GmSSL ${TEST_TEST_NAME} early data\n")

	string(REPLACE ";" " " SERVER_CMD "${TEST_SERVER_ARGS}")
	string(REPLACE ";" " " CLIENT_CMD "${TEST_CLIENT_ARGS}")

	execute_process(
		COMMAND pkill -f "gmssl ${SERVER_TOOL} -port ${TEST_PORT}"
		OUTPUT_QUIET
		ERROR_QUIET
	)

	execute_process(
		COMMAND bash -c "nohup bin/gmssl ${SERVER_CMD} > ${SERVER_LOG} 2>&1 & echo $! > ${SERVER_PID_FILE}"
		RESULT_VARIABLE SERVER_RESULT
		TIMEOUT 5
	)
	if(NOT ${SERVER_RESULT} EQUAL 0)
		message(FATAL_ERROR "server failed to start")
	endif()

	execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 1)

	execute_process(
		COMMAND bash -c "bin/gmssl ${CLIENT_CMD} > ${CLIENT_LOG} 2>&1"
		RESULT_VARIABLE CLIENT_RESULT
		TIMEOUT 30
	)

	execute_process(
		COMMAND pkill -f "gmssl ${SERVER_TOOL} -port ${TEST_PORT}"
		OUTPUT_QUIET
		ERROR_QUIET
	)
	execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 1)

	set(SERVER_LOG_CONTENT "")
	set(CLIENT_LOG_CONTENT "")
	if(EXISTS "${SERVER_LOG}")
		file(READ "${SERVER_LOG}" SERVER_LOG_CONTENT)
	endif()
	if(EXISTS "${CLIENT_LOG}")
		file(READ "${CLIENT_LOG}" CLIENT_LOG_CONTENT)
	endif()

	if(NOT ${CLIENT_RESULT} EQUAL 0)
		message(STATUS "${SERVER_LOG}:\n${SERVER_LOG_CONTENT}")
		message(STATUS "${CLIENT_LOG}:\n${CLIENT_LOG_CONTENT}")
		message(FATAL_ERROR "client failed with result ${CLIENT_RESULT}")
	endif()

	string(FIND "${CLIENT_LOG_CONTENT}" "Connection established" FOUND_INDEX)
	if(${FOUND_INDEX} EQUAL -1)
		message(STATUS "${SERVER_LOG}:\n${SERVER_LOG_CONTENT}")
		message(STATUS "${CLIENT_LOG}:\n${CLIENT_LOG_CONTENT}")
		message(FATAL_ERROR "client did not establish connection with server")
	endif()

	if(TEST_EXPECT_CLIENT_LOG)
		string(FIND "${CLIENT_LOG_CONTENT}" "${TEST_EXPECT_CLIENT_LOG}" FOUND_INDEX)
		if(${FOUND_INDEX} EQUAL -1)
			message(STATUS "${CLIENT_LOG}:\n${CLIENT_LOG_CONTENT}")
			message(FATAL_ERROR "client log does not contain expected text: ${TEST_EXPECT_CLIENT_LOG}")
		endif()
	endif()

	if(TEST_EXPECT_SERVER_LOG)
		string(FIND "${SERVER_LOG_CONTENT}" "${TEST_EXPECT_SERVER_LOG}" FOUND_INDEX)
		if(${FOUND_INDEX} EQUAL -1)
			message(STATUS "${SERVER_LOG}:\n${SERVER_LOG_CONTENT}")
			message(FATAL_ERROR "server log does not contain expected text: ${TEST_EXPECT_SERVER_LOG}")
		endif()
	endif()

	if(POLICY CMP0053)
		cmake_policy(POP)
	endif()
endfunction()
