cmake_minimum_required(VERSION 3.13)

cmake_policy(SET CMP0076 NEW)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_ENABLE_EXPORTS ON)

project(psp2cldr)

add_executable(psp2cldr
    src/psp2cldr.cc src/load.cc src/provider.cc src/context.cc src/memory_managers.cc src/psp2cldr_internals.cc
)

FILE(GLOB PSP2CLDR_CORE_HEADER
    ${PROJECT_SOURCE_DIR}/include/psp2cldr/*.h
    ${PROJECT_SOURCE_DIR}/include/psp2cldr/*.hpp
)
FILE(GLOB PSP2CLDR_UTIL_HEADER
    ${PROJECT_SOURCE_DIR}/include/psp2cldr/utility/*.h
    ${PROJECT_SOURCE_DIR}/include/psp2cldr/utility/*.hpp
)
set(PSP2CLDR_VERSION 0.2.0-alpha)
set_target_properties(psp2cldr PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    VERSION ${PSP2CLDR_VERSION}
)
target_include_directories(psp2cldr PUBLIC include)

find_package(spdlog QUIET)
if (NOT spdlog_FOUND)
    Include(FetchContent)
    FetchContent_Declare(
        spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.9.2
    )
    FetchContent_MakeAvailable(spdlog)
endif()
target_link_libraries(psp2cldr PRIVATE spdlog::spdlog)

target_link_libraries(psp2cldr PRIVATE stdc++fs)    # std::experimental::filesystem for gcc 7 and std::filesystem for gcc 8

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)
target_link_libraries(psp2cldr PRIVATE Threads::Threads)

list(APPEND CMAKE_REQUIRED_LIBRARIES ${CMAKE_DL_LIBS} Threads::Threads)
target_link_libraries(psp2cldr PRIVATE ${CMAKE_DL_LIBS})

include(CheckSymbolExists)

execute_process(COMMAND ${CMAKE_C_COMPILER} -dM -E -
                INPUT_FILE /dev/null
                OUTPUT_VARIABLE PSP2CLDR_MACROS)
string(FIND ${PSP2CLDR_MACROS} "__ARM_ARCH_7A__" FIND_ARMv7A_RET)
if (${FIND_ARMv7A_RET} GREATER "0")
    string(FIND ${PSP2CLDR_MACROS} "__ARM_PCS_VFP" FIND_ARMPCSVFP_RET)
    check_symbol_exists(sigaction "signal.h" HAVE_SIGACTION)
    check_symbol_exists(sigaltstack "signal.h" HAVE_SIGALTSTACK)

    if("${HAVE_SIGACTION}" AND "${HAVE_SIGALTSTACK}" AND ${FIND_ARMPCSVFP_RET} GREATER "0")
        message(STATUS "Using PSP2CLDR_NATIVE")
        add_compile_definitions(PSP2CLDR_NATIVE=1)
        add_compile_options(-fstack-protector-strong)
        target_sources(psp2cldr PRIVATE "include/psp2cldr/implementation/native.hpp" "src/native.cc")

    else()
        unset(HAVE_SIGACTION CACHE)
        unset(HAVE_SIGALTSTACK CACHE)
        message(FATAL_ERROR "PSP2CLDR_NATIVE requirement unsatisfied")
    endif()
else()
    message(FATAL_ERROR "Not building for ARMv7A, EMULATION mode no longer exists")
endif()

include(GNUInstallDirs)

set(pkg_config "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.pc")
set(pkgconfig_install_dir "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
configure_file("cmake/${PROJECT_NAME}.pc.in" "${pkg_config}" @ONLY)
install(FILES "${pkg_config}" DESTINATION "${pkgconfig_install_dir}")

install(FILES ${PSP2CLDR_CORE_HEADER} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/psp2cldr)
install(FILES ${PSP2CLDR_UTIL_HEADER} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/psp2cldr/utility)
install(TARGETS psp2cldr
        EXPORT psp2cldr
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
