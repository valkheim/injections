#include "dll_inject.h"
#include "ulib.h"

auto load_remote_library(HANDLE process, LPVOID dll_content, DWORD dll_size, LPVOID parameter) -> HANDLE
{
  auto reflective_loader_exported_name = "ReflectiveLoader";
  auto reflective_loader = ::ul::Export{};
  auto found = ::ul::with_export((std::ptrdiff_t)dll_content, "ReflectiveLoader", [&](::ul::Export const &xport) -> ::ul::walk_t {
    reflective_loader = xport;
    return ::ul::walk_t::WALK_STOP;
  });
  printf("try%s\n", reflective_loader.name.c_str());
  if (!found) {
    ::ul::error("Reflective loader export not found");  // missing privileges
    return nullptr;
  }

  printf("offset = %td\n", reflective_loader.offset);

  // alloc memory (RWX) in the host process for the image...
  auto remote_library_buffer = VirtualAllocEx(process, NULL, dll_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (!remote_library_buffer) puts("no remote libraru buffer");

  // write the image into the host process...
  if (!WriteProcessMemory(process, remote_library_buffer, dll_content, dll_size, NULL)) {
    ::ul::error("Cannot write the reflective library into the target process");
    return nullptr;
  }

  auto reflective_loader_remote_address = (LPTHREAD_START_ROUTINE)((ULONG_PTR)remote_library_buffer + reflective_loader.offset);
  printf("reflective_loader_remote_address %p\n", reflective_loader_remote_address);

  DWORD tid = 0;
  auto thread = CreateRemoteThread(process, nullptr, 0, reflective_loader_remote_address, parameter, 0, &tid);
  if (thread == nullptr) {
    ::ul::error("Cannot call the reflective loader of the injected library in target process");
    return nullptr;
  }

  return thread;
}

auto inject_using_reflective_dll(std::string const &&dll_path, DWORD const pid) -> bool
{
  auto status = true;
  DWORD dll_size = 0;
  DWORD read = 0;
  LPVOID dll_content = nullptr;
  HANDLE thread = nullptr;
  HANDLE process = nullptr;
  HANDLE token = nullptr;
  TOKEN_PRIVILEGES privileges;
  std::memset(&privileges, 0, sizeof(privileges));

  auto dll_file = CreateFileA(dll_path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (dll_file == INVALID_HANDLE_VALUE) {
    ::ul::error("Failed to open the DLL file");
    status = false;
    goto Exit;
  }

  dll_size = GetFileSize(dll_file, NULL);
  if (dll_size == INVALID_FILE_SIZE || dll_size == 0) {
    ::ul::error("Failed to get the DLL file size");
    status = false;
    goto Exit;
  }

  dll_content = HeapAlloc(GetProcessHeap(), 0, dll_size);
  if (!dll_content) {
    ::ul::error("Failed to get the DLL file size");
    status = false;
    goto Exit;
  }

  if (ReadFile(dll_file, dll_content, dll_size, &read, nullptr) == FALSE) {
    ::ul::error("Failed to alloc a buffer!");
    status = false;
    goto Exit;
  }

  if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid))
      AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);

    CloseHandle(token);
  }

  process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
  if (!process) {
    ::ul::error("Failed to open the target process");
    status = false;
    goto Exit;
  }

  thread = load_remote_library(process, dll_content, dll_size, nullptr);
  if (!thread) {
    ::ul::error("Failed to inject the DLL");
    status = false;
    goto Exit;
  }

  printf("[+] Injected the '%s' DLL into process %d.", dll_path.c_str(), pid);
  Sleep(5000);
  WaitForSingleObject(thread, INFINITE);

Exit:
  if (dll_content) HeapFree(GetProcessHeap(), 0, dll_content);

  if (process) CloseHandle(process);

  return status;
}