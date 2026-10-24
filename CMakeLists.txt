cmake_minimum_required(VERSION 3.20)
project(mempulse LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(mempulse src/main.cpp)
if(MSVC)
    target_compile_options(mempulse PRIVATE /W4 /permissive- /O2)
else()
    target_compile_options(mempulse PRIVATE -Wall -Wextra -O3)
endif()
