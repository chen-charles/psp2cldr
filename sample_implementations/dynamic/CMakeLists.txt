cmake_minimum_required(VERSION 3.13)

project(dynamic)

set(CMAKE_CXX_STANDARD 20)

add_library(${PROJECT_NAME} SHARED
    impl.cc
)

set(PSP2CLDR_TAG master CACHE STRING "psp2cldr branch/tag/hash")

Include(FetchContent)
if (MSVC)
    FetchContent_Declare(
        psp2cldr
        GIT_REPOSITORY https://github.com/chen-charles/psp2cldr
        GIT_TAG ${PSP2CLDR_TAG}
    )
    FetchContent_MakeAvailable(psp2cldr)
    target_link_libraries(${PROJECT_NAME} PRIVATE psp2cldr)
    target_include_directories(${PROJECT_NAME} PUBLIC psp2cldr)

    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "/GS /std:c++20 /EHsc /EHa")
else()
    find_package(PkgConfig REQUIRED)
    if (NOT psp2cldr)
        pkg_check_modules(PSP2CLDR psp2cldr)

        if (${PSP2CLDR_FOUND})
            target_link_libraries(${PROJECT_NAME} ${PSP2CLDR_LIBRARIES})
            target_include_directories(${PROJECT_NAME} PUBLIC ${PSP2CLDR_INCLUDE_DIRS})
            target_compile_options(${PROJECT_NAME} PUBLIC ${PSP2CLDR_CFLAGS_OTHER})
        else()
            FetchContent_Declare(
                psp2cldr
                GIT_REPOSITORY https://github.com/chen-charles/psp2cldr
                GIT_TAG ${PSP2CLDR_TAG}
            )
            FetchContent_MakeAvailable(psp2cldr)
            target_link_libraries(${PROJECT_NAME} PRIVATE psp2cldr)
            target_include_directories(${PROJECT_NAME} PUBLIC psp2cldr)
        endif()
    endif()

    add_definitions(-fvisibility=hidden)
    target_link_libraries(${PROJECT_NAME} PRIVATE stdc++fs)
endif()
