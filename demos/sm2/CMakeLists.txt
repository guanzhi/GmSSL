cmake_minimum_required(VERSION 3.0)
project(sm2demo)

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

add_executable(sm2keyparse sm2keyparse.c)
target_link_libraries(sm2keyparse gmssl)
