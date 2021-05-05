cmake_minimum_required(VERSION 3.12)

project(dynamic)

set (CMAKE_CXX_STANDARD 20)

include_directories(../../include)
add_library(dynamic SHARED
    impl.cc
)

if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_definitions(-fvisibility=hidden)
endif()
