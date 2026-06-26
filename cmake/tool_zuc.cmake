include("${CMAKE_CURRENT_LIST_DIR}/tool_helpers.cmake")

set(ZUC_KEY 00000000000000000000000000000000)
set(ZUC_IV 00000000000000000000000000000000)
file(WRITE tool_zuc.plain "0123456789abcdef")

gmssl_run(zuc -key ${ZUC_KEY} -iv ${ZUC_IV} -in tool_zuc.plain -out tool_zuc.cipher)
gmssl_expect_file_hex(tool_zuc.cipher "178fec4735b5b4edbfed84d4fc7cda00")
gmssl_run(zuc -key ${ZUC_KEY} -iv ${ZUC_IV} -in tool_zuc.cipher -out tool_zuc.decrypt)
gmssl_files_equal(tool_zuc.plain tool_zuc.decrypt)

gmssl_run(zuc_128_eea3
	-key 173d14ba5003731d7a60049470f00a29
	-count 0x66035492 -bearer 15 -direction 0
	-in tool_zuc.plain
	-out tool_zuc_128_eea3.cipher)
gmssl_expect_file_hex(tool_zuc_128_eea3.cipher
	"fa0f3eb52d9be1af9e521680d313c40c")
gmssl_expect_stdout("b0361765\n" zuc_128_eia3
	-key 00000000000000000000000000000000
	-count 0 -bearer 0 -direction 0 -in tool_zuc.plain)

gmssl_run(zuc256
	-key 0000000000000000000000000000000000000000000000000000000000000000
	-iv 0000000000000000000000000000000000000000000000
	-in tool_zuc.plain -out tool_zuc256.cipher)
gmssl_expect_file_hex(tool_zuc256.cipher "68e108e51a361ad5e2c509585ad9ae65")
gmssl_run(zuc256
	-key 0000000000000000000000000000000000000000000000000000000000000000
	-iv 0000000000000000000000000000000000000000000000
	-in tool_zuc256.cipher -out tool_zuc256.decrypt)
gmssl_files_equal(tool_zuc.plain tool_zuc256.decrypt)
