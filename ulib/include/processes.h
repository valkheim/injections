#pragma once

#include <Windows.h>

#include <functional>

#include "utils.h"

namespace ul
{
  void walk_processes_ids_using_enumprocess(std::function<ul::walk_t(DWORD)> callback);
  void walk_processes_ids_using_toolhelp(std::function<ul::walk_t(DWORD)> callback);
  void walk_processes_ids_using_wts(std::function<ul::walk_t(DWORD)> callback);
  auto get_processes_ids_using_enumprocess() -> std::vector<DWORD>;
  auto get_processes_ids_using_toolhelp() -> std::vector<DWORD>;
  auto get_processes_ids_using_wts() -> std::vector<DWORD>;

}  // namespace ul