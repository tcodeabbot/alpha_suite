cmake_minimum_required(VERSION 3.10)
project(guardalloc C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Debug build by default for sanitizer-style tooling
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Compiler warnings
add_compile_options(-Wall -Wextra -Wpedantic)

# Main executable
add_executable(guardalloc guardalloc.c)
