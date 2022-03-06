#include <stdio.h>
#include <windows.h>

#include "ulib.h"

int main(int argc, char *argv[])
{
  wchar_t dllPath[] =
      L"C:\\Users\\user\\Desktop\\red\\build\\x64\\dll_sample\\Debug\\dll_"
      L"sample.dll";

  printf("Injecting DLL to PID: %i\n", atoi(argv[1]));
  auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(argv[1]));
  auto remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE);
  WriteProcessMemory(hProcess, remoteBuffer, (LPVOID)dllPath, sizeof(dllPath), NULL);
  auto threatStartRoutineAddress =
      static_cast<PTHREAD_START_ROUTINE>(::ul::get_module_export("kernel32", "LoadLibraryW"));
  CreateRemoteThread(hProcess, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);
  CloseHandle(hProcess);
  return 0;
}