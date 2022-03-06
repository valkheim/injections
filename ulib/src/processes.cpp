#include "processes.h"

#include <psapi.h>     // EnumProcess
#include <tlhelp32.h>  // CreateToolhelp32Snapshot, …
#pragma comment(lib, "wtsapi32.lib")
#include <wtsapi32.h>

#include "log.h"

namespace ul
{
  void walk_processes_ids_using_enumprocess(std::function<ul::walk_t(DWORD)> callback)
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
      if (callback(pids[i]) == ::ul::walk_t::WALK_STOP) break;
    }
  }

  void walk_processes_ids_using_toolhelp(std::function<ul::walk_t(DWORD)> callback)
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
      if (callback(pe.th32ProcessID) == ::ul::walk_t::WALK_STOP) break;
    } while (::Process32Next(snapshot, &pe));
    ::CloseHandle(snapshot);
  }

  void walk_processes_ids_using_wts(std::function<ul::walk_t(DWORD)> callback)
  {
    PWTS_PROCESS_INFO info;
    DWORD count;
    if (::WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1, &info, &count) == FALSE) {
      ::ul::error("Cannot WTSEnumerateProcesses");
      return;
    }

    for (DWORD i = 0; i < count; ++i) {
      auto process = info + i;
      if (callback(process->ProcessId) == ::ul::walk_t::WALK_STOP) break;
    }

    ::WTSFreeMemory(info);
  }

  auto get_processes_ids_using_enumprocess() -> std::vector<DWORD>
  {
    auto pids = std::vector<DWORD>{};
    ::ul::walk_processes_ids_using_enumprocess([&](DWORD pid) -> ::ul::walk_t {
      pids.emplace_back(pid);
      return ::ul::walk_t::WALK_CONTINUE;
    });

    return pids;
  }

  auto get_processes_ids_using_toolhelp() -> std::vector<DWORD>
  {
    auto pids = std::vector<DWORD>{};
    ::ul::walk_processes_ids_using_toolhelp([&](DWORD pid) -> ::ul::walk_t {
      pids.emplace_back(pid);
      return ::ul::walk_t::WALK_CONTINUE;
    });

    return pids;
  }

  auto get_processes_ids_using_wts() -> std::vector<DWORD>
  {
    auto pids = std::vector<DWORD>{};
    ::ul::walk_processes_ids_using_wts([&](DWORD pid) -> ::ul::walk_t {
      pids.emplace_back(pid);
      return ::ul::walk_t::WALK_CONTINUE;
    });

    return pids;
  }
}  // namespace ul