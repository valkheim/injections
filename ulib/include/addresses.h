#pragma once

#include <Windows.h>

#include <string_view>

namespace ul
{
  auto get_module_export(std::string_view&& module_name, std::string_view&& procedure_name) -> PVOID;
}  // namespace ul