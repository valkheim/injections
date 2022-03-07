#include "addresses.h"

#include <windows.h>

#include <cstdint>

#include "log.h"
#include "nt.h"

namespace ul
{
  auto get_module_export(std::string_view&& module_name, std::string_view&& procedure_name) -> PVOID
  {
    auto handle = GetModuleHandleA(module_name.data());
    if (handle == NULL) {
      ::ul::error("Cannot GetModuleHandleA");
      return NULL;
    }

    auto procedure = GetProcAddress(handle, procedure_name.data());
    if (procedure == NULL) {
      ::ul::error("Cannot GetProcAddress");
    }

    return procedure;
  }

  void walk_exports(std::string_view const& module_path, std::function<::ul::walk_t(PVOID, std::string)> callback)
  {
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(GetModuleHandle(module_path.data()));
    auto nt_header =
        reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::ptrdiff_t>(dos_header) + dos_header->e_lfanew);

    // Invalid file exit
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || nt_header->Signature != IMAGE_NT_SIGNATURE) {
      ::ul::error("File not recognized");
      return;
    }

    // Optional header is a PIMAGE_OPTIONAL_HEADER32 or a PIMAGE_OPTIONAL_HEADER64
    auto export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<std::ptrdiff_t>(dos_header) +
        nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!export_dir) {
      ::ul::error("Cannot find export directory");
      return;
    }

    auto functions =
        reinterpret_cast<PDWORD>(reinterpret_cast<std::ptrdiff_t>(dos_header) + export_dir->AddressOfFunctions);
    auto names = reinterpret_cast<PDWORD>(reinterpret_cast<std::ptrdiff_t>(dos_header) + export_dir->AddressOfNames);
    auto ordinals =
        reinterpret_cast<PWORD>(reinterpret_cast<std::ptrdiff_t>(dos_header) + export_dir->AddressOfNameOrdinals);
    for (DWORD i = 0; i < export_dir->NumberOfFunctions; i++) {
      auto address = reinterpret_cast<PVOID>(reinterpret_cast<std::ptrdiff_t>(dos_header) + functions[ordinals[i]]);
      auto name = std::string{reinterpret_cast<char*>(dos_header) + names[i]};
      if (!address) {
        ::ul::warning("Cannot find exported address. Continue");
        break;
      }

      if (name.empty()) {
        ::ul::warning("Cannot find exported name. Continue");
        break;
      }

      if (callback(address, name) == ::ul::walk_t::WALK_STOP) break;
    }
  }
}  // namespace ul