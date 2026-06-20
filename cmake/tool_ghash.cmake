include("${CMAKE_CURRENT_LIST_DIR}/tool_helpers.cmake")

gmssl_expect_stdout("50db43e2ab4a2bbddd6e1182de2cc22b\n"
	ghash -h 0123456789abcdeffedcba9876543210 -aad_hex 001122 -in_str abc)

file(WRITE tool_ghash_input.txt "abc")
gmssl_run(ghash -h 0123456789abcdeffedcba9876543210 -aad "aad" -bin
	-in tool_ghash_input.txt -out tool_ghash.bin)
gmssl_require_file(tool_ghash.bin)
