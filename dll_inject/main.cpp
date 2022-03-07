#include <stdio.h>
#include <windows.h>

#include "ulib.h"

static auto inject_dll_using_createremotethread(std::string const &&dllPath, DWORD const pid) -> bool
{
  // https://www.apriorit.com/dev-blog/679-windows-dll-injection-for-api-hooks#dll2
  auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, DWORD(pid));
  if (hProcess == NULL) {
    ::ul::error("Cannot OpenProcess");
    return false;
  }

  auto remoteBuffer = VirtualAllocEx(hProcess, NULL, dllPath.size(), MEM_COMMIT, PAGE_READWRITE);
  if (remoteBuffer == NULL) {
    ::ul::error("Cannot VirtualAllocEx");
    return false;
  }

  if (WriteProcessMemory(hProcess, remoteBuffer, dllPath.c_str(), dllPath.size(), NULL) == 0) {
    ::ul::error("Cannot WriteProcessMemory");
    return false;
  }

  auto threatStartRoutineAddress =
      static_cast<PTHREAD_START_ROUTINE>(::ul::get_module_export("kernel32", "LoadLibraryA"));
  if (threatStartRoutineAddress == NULL) {
    ::ul::error("Cannot get LoadLibraryA");
    return false;
  }

  auto remoteThread = CreateRemoteThread(hProcess, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);
  if (remoteThread == NULL) {
    ::ul::error("Cannot CreateRemoteThread");
    return false;
  }

  if (WaitForSingleObject(remoteThread, INFINITE) == WAIT_FAILED) {
    ::ul::error("Cannot WaitForSingleObject");
    return false;
  }

  if (VirtualFreeEx(hProcess, remoteBuffer, dllPath.size(), MEM_RELEASE) == 0) {
    ::ul::error("Cannot VirtualFreeEx");
    return false;
  }

  if (CloseHandle(remoteThread) == 0) {
    ::ul::error("Cannot CloseHandle for remote thread");
    return false;
  }

  if (CloseHandle(hProcess) == 0) {
    ::ul::error("Cannot CloseHandle for opened process");
    return false;
  }

  return true;
}

int main(int argc, char *argv[])
{
  auto dllPath = std::string{argv[1]};
  auto pid = std::atoi(argv[2]);
  printf("Injecting DLL %s to PID: %zd\n", dllPath.c_str(), dllPath.size());
  if (inject_dll_using_createremotethread(std::move(dllPath), pid) == false) {
    ::ul::error("Cannot inject DLL using the CreateRemoteThread technique");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}