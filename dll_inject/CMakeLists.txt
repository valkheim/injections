file(GLOB_RECURSE sources "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_executable(dll_inject ${sources})
target_include_directories(dll_inject PUBLIC "../ulib/include/public")
target_link_libraries(dll_inject ulib)