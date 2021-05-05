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
  
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -nostdlib")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -nostdlib")
  
  link_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
  )
  
  add_executable(${PROJECT_NAME}
    ${PROJECT_NAME}.c
  )
  
  target_link_libraries(${PROJECT_NAME}
    $ENV{VITASDK}/arm-vita-eabi/lib/libSceLibKernel_stub.a
    $ENV{VITASDK}/arm-vita-eabi/lib/libSceKernelThreadMgr_stub.a
  )
  
  vita_create_self(${PROJECT_NAME}.self ${PROJECT_NAME})
endforeach()

