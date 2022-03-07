#pragma once

#include <Windows.h>

#include "addresses.h"

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

typedef LONG KPRIORITY;

typedef struct _CLIENT_ID {
  DWORD UniqueProcess;
  DWORD UniqueThread;
} CLIENT_ID;

typedef enum _THREAD_STATE {
  StateInitialized,
  StateReady,
  StateRunning,
  StateStandby,
  StateTerminated,
  StateWait,
  StateTransition,
  StateUnknown
} THREAD_STATE;

typedef struct _SYSTEM_THREAD {
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER CreateTime;
  ULONG WaitTime;
  PVOID StartAddress;
  CLIENT_ID ClientId;
  KPRIORITY Priority;
  KPRIORITY BasePriority;
  ULONG ContextSwitchCount;
  THREAD_STATE State;
  LONG WaitReason;
} SYSTEM_THREAD, *PSYSTEM_THREAD;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING;

typedef struct _VM_COUNTERS {
#ifdef _WIN64
  SIZE_T PeakVirtualSize;
  SIZE_T PageFaultCount;
  SIZE_T PeakWorkingSetSize;
  SIZE_T WorkingSetSize;
  SIZE_T QuotaPeakPagedPoolUsage;
  SIZE_T QuotaPagedPoolUsage;
  SIZE_T QuotaPeakNonPagedPoolUsage;
  SIZE_T QuotaNonPagedPoolUsage;
  SIZE_T PagefileUsage;
  SIZE_T PeakPagefileUsage;
  SIZE_T VirtualSize;
#else
  SIZE_T PeakVirtualSize;
  SIZE_T VirtualSize;
  ULONG PageFaultCount;
  SIZE_T PeakWorkingSetSize;
  SIZE_T WorkingSetSize;
  SIZE_T QuotaPeakPagedPoolUsage;
  SIZE_T QuotaPagedPoolUsage;
  SIZE_T QuotaPeakNonPagedPoolUsage;
  SIZE_T QuotaNonPagedPoolUsage;
  SIZE_T PagefileUsage;
  SIZE_T PeakPagefileUsage;
#endif
} VM_COUNTERS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
  ULONG NextEntryDelta;
  ULONG ThreadCount;
  ULONG Reserved1[6];
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ProcessName;
  KPRIORITY BasePriority;
  ULONG ProcessId;
  ULONG InheritedFromProcessId;
  ULONG HandleCount;
  ULONG Reserved2[2];
  VM_COUNTERS VmCounters;
#if _WIN32_WINNT >= 0x500
  IO_COUNTERS IoCounters;
#endif
  SYSTEM_THREAD Threads[ANYSIZE_ARRAY];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_MODULE {
  ULONG Reserved1;
  ULONG Reserved2;
  ULONG Reserved3;
  PVOID ImageBaseAddress;
  ULONG ImageSize;
  ULONG Flags;
  WORD Id;
  WORD Rank;
  WORD LoadCount;
  WORD NameOffset;
  CHAR Name[MAX_PATH - 4];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
  ULONG ModulesCount;
  SYSTEM_MODULE Modules[ANYSIZE_ARRAY];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
  SystemProcessAndThreadInformation = 0x05,
  SystemModuleInformation = 0x0b
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                                    __inout PVOID SystemInformation, __in ULONG SystemInformationLength,
                                                    __out_opt PULONG ReturnLength);

namespace ul
{

  template <typename T>
  struct SystemInformationClass : std::false_type {
  };
  template <>
  struct SystemInformationClass<SYSTEM_PROCESS_INFORMATION> {
    static constexpr auto value = SystemModuleInformation;
  };
  template <>
  struct SystemInformationClass<PSYSTEM_MODULE_INFORMATION> {
    static constexpr auto value = SystemModuleInformation;
  };

  template <typename SystemInformation>
  SystemInformation get_system_informations()
  {
    auto NtQuerySystemInformation =
        (_NtQuerySystemInformation)::ul::get_module_export("ntdll.dll", "NtQuerySystemInformation");
    static_assert(SystemInformationClass<SystemInformation>::value, "Missing SystemInformationClass specialization");
    auto system_information_class = SystemInformationClass<SystemInformation>::value;
    SystemInformation system_informations = NULL;
    ULONG length = 0x1000;
    for (;;) {
      system_informations =
          (SystemInformation)VirtualAlloc(NULL, length, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      if (system_informations == NULL) break;

      auto status = NtQuerySystemInformation(system_information_class, system_informations, length, &length);
      if (status != STATUS_INFO_LENGTH_MISMATCH) break;

      if (system_informations != NULL) VirtualFree(system_informations, 0, MEM_RELEASE);

      length <<= 2;
    }

    return system_informations;
  }
}  // namespace ul