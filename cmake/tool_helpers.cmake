set(GMSSL_BIN bin/gmssl)

function(gmssl_run)
	execute_process(
		COMMAND ${GMSSL_BIN} ${ARGN}
		RESULT_VARIABLE TEST_RESULT
		ERROR_VARIABLE TEST_STDERR
		OUTPUT_VARIABLE TEST_STDOUT
	)
	if(NOT TEST_RESULT EQUAL 0)
		message(FATAL_ERROR "command failed: ${GMSSL_BIN} ${ARGN}\nstderr: ${TEST_STDERR}\nstdout: ${TEST_STDOUT}")
	endif()
endfunction()

function(gmssl_run_capture out_var)
	execute_process(
		COMMAND ${GMSSL_BIN} ${ARGN}
		RESULT_VARIABLE TEST_RESULT
		ERROR_VARIABLE TEST_STDERR
		OUTPUT_VARIABLE TEST_STDOUT
	)
	if(NOT TEST_RESULT EQUAL 0)
		message(FATAL_ERROR "command failed: ${GMSSL_BIN} ${ARGN}\nstderr: ${TEST_STDERR}\nstdout: ${TEST_STDOUT}")
	endif()
	set(${out_var} "${TEST_STDOUT}" PARENT_SCOPE)
endfunction()

function(gmssl_expect_stdout expected)
	gmssl_run_capture(TEST_STDOUT ${ARGN})
	if(NOT TEST_STDOUT STREQUAL "${expected}")
		message(FATAL_ERROR "unexpected stdout for ${GMSSL_BIN} ${ARGN}\nexpected: ${expected}\nactual: ${TEST_STDOUT}")
	endif()
endfunction()

function(gmssl_require_file file)
	if(NOT EXISTS "${file}")
		message(FATAL_ERROR "generated file does not exist: ${file}")
	endif()
endfunction()

function(gmssl_files_equal expected actual)
	gmssl_require_file("${expected}")
	gmssl_require_file("${actual}")
	file(SHA256 "${expected}" EXPECTED_HASH)
	file(SHA256 "${actual}" ACTUAL_HASH)
	if(NOT EXPECTED_HASH STREQUAL ACTUAL_HASH)
		message(FATAL_ERROR "file mismatch: ${expected} ${actual}")
	endif()
endfunction()

function(gmssl_expect_file_hex file expected_hex)
	gmssl_require_file("${file}")
	file(READ "${file}" ACTUAL_HEX HEX)
	string(TOLOWER "${ACTUAL_HEX}" ACTUAL_HEX)
	string(TOLOWER "${expected_hex}" EXPECTED_HEX)
	if(NOT ACTUAL_HEX STREQUAL EXPECTED_HEX)
		message(FATAL_ERROR "unexpected hex in ${file}\nexpected: ${EXPECTED_HEX}\nactual: ${ACTUAL_HEX}")
	endif()
endfunction()

function(gmssl_expect_file_text file expected_text)
	gmssl_require_file("${file}")
	file(READ "${file}" ACTUAL_TEXT)
	if(NOT ACTUAL_TEXT STREQUAL "${expected_text}")
		message(FATAL_ERROR "unexpected text in ${file}\nexpected: ${expected_text}\nactual: ${ACTUAL_TEXT}")
	endif()
endfunction()
