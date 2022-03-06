file(GLOB_RECURSE sources "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(ulib_test ${sources})

target_include_directories(ulib_test
    PUBLIC ../../ulib/include/public
)

target_link_libraries(
  ulib_test
  ulib
  gtest_main
)
