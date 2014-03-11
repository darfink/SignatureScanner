cmake_minimum_required(VERSION 2.6)
project(SignatureScanner)

# Our project version
set(SignatureScanner_VERSION_MAJOR 0)
set(SignatureScanner_VERSION_MINOR 1)

if(UNIX)
    message(status "Setting GCC flags")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb3 -Wall -std=c++11")
else()
    message(status "Settings MSVC flags")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHc-")
endif()

message(status "** CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")

add_library(libscanner SignatureScanner.cpp)
#set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
#
#set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
#set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})
#
#set(PROJECT_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
#
#include_directories("${PROJECT_INCLUDE_DIR}")
#include_directories("${PROJECT_SOURCE_DIR}")
