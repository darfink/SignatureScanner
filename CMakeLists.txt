cmake_minimum_required(VERSION 2.8)
project(SignatureScanner)

# Our project version
set(SignatureScanner_VERSION_MAJOR 0)
set(SignatureScanner_VERSION_MINOR 1)

set(CMAKE_BINARY_DIR ${PROJECT_SOURCE_DIR}/build)

# The output directory for executables and libraries
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

include_directories(${PROJECT_SOURCE_DIR}/include)

# All source files are in the 'src' folder
set(SOURCES src/SignatureScanner.cpp)

if(UNIX)
    message("Setting GCC flags")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra -Wall -std=c++11")
else()
    message("Settings MSVC flags")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHc-")
endif()

# Tell the user about the flags we will use
message("** CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")

# We will create a library
add_library(scanner ${SOURCES})
