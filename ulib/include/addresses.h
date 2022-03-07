#pragma once

#include <Windows.h>

#include <functional>
#include <string>
#include <string_view>

#include "utils.h"

namespace ul
{
  auto get_module_export(std::string_view&& module_name, std::string_view&& procedure_name) -> PVOID;
  void walk_exports(std::string_view const& module_path, std::function<::ul::walk_t(PVOID, std::string)> callback);
}  // namespace ul