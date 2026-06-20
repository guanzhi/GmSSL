include("${CMAKE_CURRENT_LIST_DIR}/tool_helpers.cmake")

set(ZUC_KEY 00000000000000000000000000000000)
set(ZUC_IV 00000000000000000000000000000000)
file(WRITE tool_zuc.plain "0123456789abcdef")

gmssl_run(zuc -key ${ZUC_KEY} -iv ${ZUC_IV} -in tool_zuc.plain -out tool_zuc.cipher)
gmssl_expect_file_hex(tool_zuc.cipher "178fec4735b5b4edbfed84d4fc7cda00")
gmssl_run(zuc -key ${ZUC_KEY} -iv ${ZUC_IV} -in tool_zuc.cipher -out tool_zuc.decrypt)
gmssl_files_equal(tool_zuc.plain tool_zuc.decrypt)
