cmake_minimum_required(VERSION 3.12)

cmake_policy(SET CMP0076 NEW)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/impls)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_ENABLE_EXPORTS ON)

project(psp2cldr)
option (BUILD_SAMPLES "build sample implementations" ON)

add_executable(psp2cldr
    src/psp2cldr.cc src/load.cc src/provider.cc src/context.cc src/memory_managers.cc src/psp2cldr_internals.cc
)
include_directories(include)


find_package(spdlog REQUIRED)
target_link_libraries(psp2cldr PRIVATE spdlog::spdlog)

target_link_libraries(psp2cldr PRIVATE stdc++fs)    # std::experimental::filesystem for gcc 7 and std::filesystem for gcc 8

include(CheckSymbolExists)
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)   # pthread_sigqueue etc.
list(APPEND CMAKE_REQUIRED_LIBRARIES ${CMAKE_DL_LIBS})
check_symbol_exists(dlmopen "dlfcn.h" HAVE_DLMOPEN)

target_link_libraries(psp2cldr PRIVATE ${CMAKE_DL_LIBS})

execute_process(COMMAND ${CMAKE_C_COMPILER} -dM -E -
                INPUT_FILE /dev/null
                OUTPUT_VARIABLE PSP2CLDR_MACROS)
string(FIND ${PSP2CLDR_MACROS} "__ARM_ARCH_7A__" FIND_ARMv7A_RET)
if (${FIND_ARMv7A_RET} GREATER "0")
    check_symbol_exists(setcontext "ucontext.h" HAVE_SETCONTEXT)
    check_symbol_exists(getcontext "ucontext.h" HAVE_GETCONTEXT)
    check_symbol_exists(sigqueue "signal.h" HAVE_SIGQUEUE)
    check_symbol_exists(sigaction "signal.h" HAVE_SIGACTION)

    if("${HAVE_SETCONTEXT}" AND "${HAVE_GETCONTEXT}" AND "${HAVE_SIGQUEUE}" AND "${HAVE_SIGQUEUE}")
        message(STATUS "Using PSP2CLDR_NATIVE")
        add_compile_definitions(PSP2CLDR_NATIVE=1)
        target_sources(psp2cldr PRIVATE "include/psp2cldr/native.hpp" "src/native.cc")

    else()
        unset(HAVE_SETCONTEXT CACHE)
        unset(HAVE_GETCONTEXT CACHE)
        unset(HAVE_SIGQUEUE CACHE)
        unset(HAVE_SIGACTION CACHE)
        message(FATAL_ERROR "PSP2CLDR_NATIVE requirement unsatisfied")
    endif() 
endif()

if (${BUILD_SAMPLES})
    add_subdirectory(sample_implementations)
endif()

if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/implementations")
    add_subdirectory(implementations)
endif()
