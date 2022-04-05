#pragma once

#include <windows.h>

#include <format>

#include "ulib.h"

#if _WIN64
static constexpr uint8_t g_shellcode[206] = ul::shellcodes::x64::pop_calc;
#else
static constexpr uint8_t g_shellcode[201] = ul::shellcodes::x86::pop_calc;
#endif

auto inject_thread(DWORD const pid) -> bool;
auto hijack_thread(std::string const& process_name) -> bool;
auto apc_queue(std::string const &process_name) -> bool;
auto early_apc_queue(std::string const &process_name) -> bool;
auto memory_view(DWORD const pid) -> bool;