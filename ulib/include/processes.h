#pragma once

#include <Windows.h>

#include <functional>
#include <optional>
#include <vector>

#include "utils.h"

namespace ul
{
  using Pid = DWORD;

  struct Process {
    Pid pid;
    std::optional<std::string> path;
    std::optional<std::string> name;
  };

  using Processes = std::vector<Process>;

  void walk_processes_ids_using_enumprocess(std::function<ul::walk_t(::ul::Process)> callback);
  void walk_processes_ids_using_toolhelp(std::function<ul::walk_t(::ul::Process)> callback);
  void walk_processes_ids_using_wts(std::function<ul::walk_t(::ul::Process)> callback);
  auto get_processes_ids_using_enumprocess() -> ::ul::Processes;
  auto get_processes_ids_using_toolhelp() -> ::ul::Processes;
  auto get_processes_ids_using_wts() -> ::ul::Processes;
  [[nodiscard]] auto with_process_using_enumprocess(std::string_view&& requested_name,
                                                    std::function<::ul::walk_t(::ul::Process)> callback) -> bool;
  [[nodiscard]] auto with_process_using_toolhelp(std::string_view&& requested_name,
                                                 std::function<::ul::walk_t(::ul::Process)> callback) -> bool;
  [[nodiscard]] auto with_process_using_wts(std::string_view&& requested_name,
                                            std::function<::ul::walk_t(::ul::Process)> callback) -> bool;
}  // namespace ul