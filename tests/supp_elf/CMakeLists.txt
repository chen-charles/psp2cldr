FILE(GLOB SOURCES *.c)
foreach(SRC_FILENAME ${SOURCES})
  get_filename_component(SRC_NAME ${SRC_FILENAME} NAME_WLE)
  project(${SRC_NAME})
  
  include("${VITASDK}/share/vita.cmake" REQUIRED)
  set (CMAKE_SHARED_LINKER_FLAGS "-Wl,--hash-style=sysv -nostdlib -lgcc")
  SET_PROPERTY(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)

  add_library(${PROJECT_NAME} SHARED
    ${SRC_FILENAME}
  )

endforeach()

