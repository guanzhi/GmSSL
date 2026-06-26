include("${CMAKE_CURRENT_LIST_DIR}/tool_helpers.cmake")

gmssl_expect_stdout("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0\n"
	sm3 -in_str abc)

file(WRITE tool_sm3_input.txt "abc")
gmssl_expect_stdout("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0\n"
	sm3 -hex -in tool_sm3_input.txt)
gmssl_run(sm3 -bin -in tool_sm3_input.txt -out tool_sm3.bin)
gmssl_expect_file_hex(tool_sm3.bin "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")

gmssl_expect_stdout("28d8a61be67d8bf7652c4eda7092b612f88be62184f55005c57ddf076e764199\n"
	sm3_hmac -key 0123456789abcdeffedcba9876543210 -in_str abc)
gmssl_run(sm3_hmac -key 0123456789abcdeffedcba9876543210 -bin -in tool_sm3_input.txt -out tool_sm3_hmac.bin)
gmssl_expect_file_hex(tool_sm3_hmac.bin "28d8a61be67d8bf7652c4eda7092b612f88be62184f55005c57ddf076e764199")

gmssl_expect_stdout("df6b713d38d5a35df6861959e529ed22\n"
	sm3_pbkdf2 -pass password -salt 0011223344556677 -iter 10000 -outlen 16 -hex)
gmssl_run(sm3_pbkdf2 -pass password -salt 0011223344556677 -iter 10000 -outlen 16 -bin -out tool_sm3_pbkdf2.bin)
gmssl_expect_file_hex(tool_sm3_pbkdf2.bin "df6b713d38d5a35df6861959e529ed22")
