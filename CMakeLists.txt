cmake_minimum_required(VERSION 3.10)
project("challenge")

message(STATUS "**************** Building challenge ****************")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(${PROJECT_NAME} challenge.cpp)

include_directories("/usr/local/ssl/include" "/usr/local/include/libcryptosec/" "/opt/libp11//include/")
link_libraries(crypto)
link_directories("/usr/local/ssl/lib")

target_compile_options(${PROJECT_NAME} PRIVATE -O0 -Wall -c -pthread)

target_link_libraries(${PROJECT_NAME} "/usr/local/lib64/libcryptosec.so")