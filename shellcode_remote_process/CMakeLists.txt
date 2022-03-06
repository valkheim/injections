file(GLOB_RECURSE sources "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_executable(shellcode_remote_process ${sources})
target_include_directories(shellcode_remote_process PUBLIC "../ulib/include/public")
target_link_libraries(shellcode_remote_process ulib)