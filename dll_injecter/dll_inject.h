#pragma once

#include <stdio.h>
#include <windows.h>
#include <string>

auto inject_dll_using_createremotethread(std::string const &&dllPath, DWORD const pid) -> bool;
auto inject_using_reflective_dll(std::string const &&dllPath, DWORD const pid) -> bool;