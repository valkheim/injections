cmake_minimum_required(VERSION 3.2 FATAL_ERROR)

set(CMAKE_CXX_STANDARD 23)

project(sample)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

include(ClangFormat)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(GOOGLETEST_VERSION 1.11.0)
add_subdirectory(third_party/googletest)

list(APPEND targets ulib shellcode_local_process shellcode_remote_process dll_sample dll_inject)
foreach(target IN ITEMS ${targets})
    message(STATUS "Handle ${target}")
    add_subdirectory(${target})
    target_clangformat_setup(${target})
endforeach()