#include "addresses.h"

#include <windows.h>

#include "log.h"

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
}  // namespace ul