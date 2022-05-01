cmake_minimum_required(VERSION 3.0)
project(GmSSL)

set(CMAKE_MACOSX_RPATH 1)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

include_directories(include)

add_library(sdf SHARED sdf_dummy.c)
SET_TARGET_PROPERTIES(sdf PROPERTIES VERSION 3.0 SOVERSION 3)

add_executable(
	sdfutil
	sdfutil.c
	sdf_lib.c
	sdf_ext.c
	sdf_meth.c
	sdf_sansec.c
)

INSTALL(TARGETS sdfutil RUNTIME DESTINATION bin)

