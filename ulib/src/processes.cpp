#include "processes.h"

#include <psapi.h>     // EnumProcess
#include <tlhelp32.h>  // CreateToolhelp32Snapshot, …
#pragma comment(lib, "wtsapi32.lib")
#include <wtsapi32.h>

#include "log.h"
#include "utils.h"

namespace ul
{
  namespace
  {
    auto get_process_image_path(::ul::Pid const pid) -> std::optional<std::string>
    {
      auto process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
      if (!process) {
        ::ul::warning("Cannot OpenProcess");
        return std::nullopt;
      }

      char name[MAX_PATH];
      DWORD size = MAX_PATH;
      auto count = ::QueryFullProcessImageNameA(process, 0, name, &size);
      if (count == 0) {
        ::ul::warning("Cannot QueryFullProcessImageNameA");
        return std::nullopt;
      }

      return std::string{name};
    }

    auto get_process_from_pid(::ul::Pid const pid) -> ::ul::Process
    {
      auto path = ::ul::get_process_image_path(pid);
      std::optional<std::string> name = std::nullopt;
      if (path) name = ::ul::base_name(*path);
      return ::ul::Process{pid, path, name};
    }
  }  // namespace

  void walk_processes_ids_using_enumprocess(std::function<ul::walk_t(::ul::Process)> callback)
  {
    auto count = std::size_t{0};
    auto maxCount = std::size_t{256};
    std::unique_ptr<DWORD[]> pids;
    for (;;) {
      pids = std::make_unique<DWORD[]>(maxCount);
      DWORD actualSize = 0;
      if (::EnumProcesses(pids.get(), static_cast<DWORD>(maxCount) * sizeof(DWORD), &actualSize) == FALSE) {
        ::ul::error("Cannot EnumProcesses");
        break;
      }

      count = actualSize / sizeof(DWORD);
      if (count < maxCount) {
        break;
      }

      maxCount *= 2;  // Golden ratio or 1.5 would be more efficient
    }

    for (unsigned i = 0; i < count; ++i) {
      if (callback(::ul::get_process_from_pid((pids[i]))) == ::ul::walk_t::WALK_STOP) break;
    }
  }

  void walk_processes_ids_using_toolhelp(std::function<ul::walk_t(::ul::Process)> callback)
  {
    auto snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
      ::ul::error("Cannot CreateToolhelp32Snapshot");
      return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (::Process32First(snapshot, &pe) == FALSE) {
      ::ul::error("Cannot Process32First");
      ::CloseHandle(snapshot);
      return;
    }

    do {
      // name from pe.szExeFile
      // path from Module32First() -> szExePath or QueyFullProcessingImageName
      if (callback(::ul::get_process_from_pid(pe.th32ProcessID)) == ::ul::walk_t::WALK_STOP) break;
    } while (::Process32Next(snapshot, &pe));
    ::CloseHandle(snapshot);
  }

  void walk_processes_ids_using_wts(std::function<ul::walk_t(::ul::Process)> callback)
  {
    PWTS_PROCESS_INFO info;
    DWORD count;
    if (::WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1, &info, &count) == FALSE) {
      ::ul::error("Cannot WTSEnumerateProcesses");
      return;
    }

    for (DWORD i = 0; i < count; ++i) {
      auto process = info + i;
      // name from process->pProcessName
      if (callback(::ul::get_process_from_pid(process->ProcessId)) == ::ul::walk_t::WALK_STOP) break;
    }

    ::WTSFreeMemory(info);
  }

  auto get_processes_ids_using_enumprocess() -> ::ul::Processes
  {
    auto processes = ::ul::Processes{};
    ::ul::walk_processes_ids_using_enumprocess([&](::ul::Process process) -> ::ul::walk_t {
      processes.emplace_back(process);
      return ::ul::walk_t::WALK_CONTINUE;
    });

    return processes;
  }

  auto get_processes_ids_using_toolhelp() -> ::ul::Processes
  {
    auto processes = ::ul::Processes{};
    ::ul::walk_processes_ids_using_toolhelp([&](::ul::Process process) -> ::ul::walk_t {
      processes.emplace_back(process);
      return ::ul::walk_t::WALK_CONTINUE;
    });

    return processes;
  }

  auto get_processes_ids_using_wts() -> ::ul::Processes
  {
    auto processes = ::ul::Processes{};
    ::ul::walk_processes_ids_using_wts([&](::ul::Process process) -> ::ul::walk_t {
      processes.emplace_back(process);
      return ::ul::walk_t::WALK_CONTINUE;
    });

    return processes;
  }

  auto with_process_using_enumprocess(std::string_view&& requested_name, std::function<::ul::walk_t(::ul::Process)> callback) -> bool
  {
    auto found = false;
    ::ul::walk_processes_ids_using_enumprocess([&](::ul::Process process) -> ::ul::walk_t {
      if (!process.name) {
        return ::ul::walk_t::WALK_CONTINUE;
      }

      if (*process.name != requested_name) {
        return ::ul::walk_t::WALK_CONTINUE;
      }

      found = true;
      return callback(process);
    });

    return found;
  }

  auto with_process_using_toolhelp(std::string_view&& requested_name, std::function<::ul::walk_t(::ul::Process)> callback) -> bool
  {
    auto found = false;
    ::ul::walk_processes_ids_using_toolhelp([&](::ul::Process process) -> ::ul::walk_t {
      if (!process.name) {
        return ::ul::walk_t::WALK_CONTINUE;
      }

      if (*process.name != requested_name) {
        return ::ul::walk_t::WALK_CONTINUE;
      }

      found = true;
      return callback(process);
    });

    return found;
  }

  auto with_process_using_wts(std::string_view&& requested_name, std::function<::ul::walk_t(::ul::Process)> callback) -> bool
  {
    auto found = false;
    ::ul::walk_processes_ids_using_wts([&](::ul::Process process) -> ::ul::walk_t {
      if (!process.name) {
        return ::ul::walk_t::WALK_CONTINUE;
      }

      if (*process.name != requested_name) {
        return ::ul::walk_t::WALK_CONTINUE;
      }

      found = true;
      return callback(process);
    });

    return found;
  }
}  // namespace ul