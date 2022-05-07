cmake_minimum_required(VERSION 3.0)
project(sm3demo)

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

add_executable(sm3demo sm3demo.c)
target_link_libraries(sm3demo gmssl)
