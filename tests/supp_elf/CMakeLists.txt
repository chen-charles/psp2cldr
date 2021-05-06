cmake_minimum_required(VERSION 3.10)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

FILE(GLOB SOURCES *.c)
foreach(SRC_FILENAME ${SOURCES})
  get_filename_component(SRC_NAME ${SRC_FILENAME} NAME_WLE)
  project(${SRC_NAME})
  include("${VITASDK}/share/vita.cmake" REQUIRED)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
  set (CMAKE_SHARED_LINKER_FLAGS "-Wl,--hash-style=sysv -nostdlib")
  SET_PROPERTY(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)

  add_library(${PROJECT_NAME} SHARED
    ${SRC_FILENAME}
  )

endforeach()

