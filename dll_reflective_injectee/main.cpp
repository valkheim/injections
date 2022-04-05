#include <cstddef>

#include "reflective.h"
#include "ulib.h"  // nt definitions

extern "C" __declspec(dllexport) bool example()
{
  MessageBoxA(NULL, "example", "example", NULL);
  return true;
}

__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }

__forceinline auto ror(DWORD d) -> DWORD { return _rotr(d, 13); }

__forceinline auto hash(char *value) -> DWORD
{
  auto hash_value = 0;
  do {
    hash_value = ror(hash_value);
    hash_value += *value;
  } while (*++value);

  return hash_value;
}

__forceinline auto get_peb() -> std::ptrdiff_t
{
#ifdef _WIN64
  return __readgsqword(0x60);
#else
  return __readfsdword(0x30);
#endif
}

__forceinline auto hash_module_name(std::ptrdiff_t module) -> DWORD
{
  auto name = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)module)->BaseDllName.pBuffer;
  DWORD hash_value = 0;
  for (auto length = ((PLDR_DATA_TABLE_ENTRY)module)->BaseDllName.Length; length > 0; length--, name++) {
    hash_value = ror((DWORD)hash_value);
    if (*((BYTE *)name) >= 'a')
      hash_value += *((BYTE *)name) - ' ';
    else
      hash_value += *((BYTE *)name);
  }

  return hash_value;
}

__forceinline auto find_module(DWORD const expected_hash_value) -> LPVOID
{
  auto peb = get_peb();
  auto base = (ULONG_PTR)((_PPEB)peb)->pLdr;
  auto module = (ULONG_PTR)((PPEB_LDR_DATA)base)->InMemoryOrderModuleList.Flink;
  while (module) {
    if (hash_module_name(module) == expected_hash_value) return (LPVOID)module;

    module = *(std::uintptr_t *)module;
  }

  return nullptr;
}

__forceinline auto find_export(ULONG_PTR module, DWORD const requested_hash_value) -> LPVOID
{
  ULONG_PTR base = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)module)->DllBase;
  ULONG_PTR uiExportDir = base + ((PIMAGE_DOS_HEADER)base)->e_lfanew;
  ULONG_PTR uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  uiExportDir = (base + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);
  uiNameArray = (base + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);
  ULONG_PTR uiNameOrdinals = (base + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);
  while (true) {  // loop number of names/functions
    auto dwHashValue = hash((char *)(base + (*(std::uint32_t *)(uiNameArray))));
    if (dwHashValue == requested_hash_value) {
      auto uiAddressArray = (base + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions) + *((std::uint16_t *)uiNameOrdinals) * sizeof(DWORD);
      return (LPVOID)(base + *((std::uint32_t *)uiAddressArray));
    }

    uiNameArray += sizeof(DWORD);
    uiNameOrdinals += sizeof(WORD);
  }

  return nullptr;
}

extern "C" __declspec(dllexport) ULONG_PTR ReflectiveLoader(LPVOID parameter)
{
  // Retrieve the kernels exports for the functions our loader needs

  auto kernel32_module = (ULONG_PTR)find_module(KERNEL32DLL_HASH);
  auto ntdll_module = (ULONG_PTR)find_module(NTDLLDLL_HASH);

  auto pLoadLibraryA = (_LoadLibrary)find_export(kernel32_module, LOADLIBRARYA_HASH);
  auto pGetProcAddress = (_GetProcAddress)find_export(kernel32_module, GETPROCADDRESS_HASH);
  auto pVirtualAlloc = (_VirtualAlloc)find_export(kernel32_module, VIRTUALALLOC_HASH);
  auto pNtFlushInstructionCache = (_NtFlushInstructionCache)find_export(ntdll_module, NTFLUSHINSTRUCTIONCACHE_HASH);

  // Load our image into a new permanent location in memory...

  auto base_src = (std::ptrdiff_t)::ul::backwards_to_base_image_address(caller());
  auto header = base_src + ((PIMAGE_DOS_HEADER)base_src)->e_lfanew;
  auto base_dst =
      (ULONG_PTR)pVirtualAlloc(nullptr, ((PIMAGE_NT_HEADERS)header)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

  auto headers_size = ((PIMAGE_NT_HEADERS)header)->OptionalHeader.SizeOfHeaders;
  auto base_src_cpy = base_src;
  auto base_dst_cpy = base_dst;
  while (headers_size--) *(BYTE *)base_dst_cpy++ = *(BYTE *)base_src_cpy++;

  // Load in all of our sections...

  auto section = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)header)->OptionalHeader + ((PIMAGE_NT_HEADERS)header)->FileHeader.SizeOfOptionalHeader);
  auto nsections = ((PIMAGE_NT_HEADERS)header)->FileHeader.NumberOfSections;
  while (nsections--) {
    auto section_size = ((PIMAGE_SECTION_HEADER)section)->SizeOfRawData;
    auto section_src = (base_src + ((PIMAGE_SECTION_HEADER)section)->PointerToRawData);
    auto section_dst = (base_dst + ((PIMAGE_SECTION_HEADER)section)->VirtualAddress);
    while (section_size--) *(BYTE *)section_dst++ = *(BYTE *)section_src++;
    section += sizeof(IMAGE_SECTION_HEADER);
  }

  // Process our images import table

  auto import_dir = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)header)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (((PIMAGE_DATA_DIRECTORY)import_dir)->Size) {
    auto import = (base_dst + ((PIMAGE_DATA_DIRECTORY)import_dir)->VirtualAddress);
    while (((PIMAGE_IMPORT_DESCRIPTOR)import)->Name) {
      // Load the imported module into memory
      auto imported_module = (ULONG_PTR)pLoadLibraryA((LPCSTR)(base_dst + ((PIMAGE_IMPORT_DESCRIPTOR)import)->Name));
      // VA of the OriginalFirstThunk
      auto thunk = (base_dst + ((PIMAGE_IMPORT_DESCRIPTOR)import)->OriginalFirstThunk);
      // VA of the IAT (via first thunk not origionalfirstthunk)
      auto iat_entry = (base_dst + ((PIMAGE_IMPORT_DESCRIPTOR)import)->FirstThunk);
      // importing by ordinal if no name present
      while (*(std::uintptr_t *)iat_entry) {
        if (thunk && ((PIMAGE_THUNK_DATA)thunk)->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
          auto import_base = imported_module + ((PIMAGE_DOS_HEADER)imported_module)->e_lfanew;
          auto import_export_dir = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)import_base)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
          import_base = (imported_module + ((PIMAGE_DATA_DIRECTORY)import_export_dir)->VirtualAddress);
          auto address = (imported_module + ((PIMAGE_EXPORT_DIRECTORY)import_base)->AddressOfFunctions) +
                         ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)thunk)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)import_base)->Base) * sizeof(DWORD));
          *(std::uintptr_t *)iat_entry = (imported_module + (*(std::uint32_t *)address));
        } else {
          import_dir = (base_dst + *(std::uintptr_t *)iat_entry);
          *(std::uintptr_t *)iat_entry = (ULONG_PTR)pGetProcAddress((HMODULE)imported_module, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)import_dir)->Name);
        }

        iat_entry += sizeof(ULONG_PTR);
        if (thunk) thunk += sizeof(ULONG_PTR);
      }

      import += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
  }

  // Process all of our images relocations...

  // calculate the base address delta and perform relocations (even if we load at desired image base)
  auto base_delta = base_dst - ((PIMAGE_NT_HEADERS)header)->OptionalHeader.ImageBase;
  auto reloc_dir = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)header)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (((PIMAGE_DATA_DIRECTORY)reloc_dir)->Size) {
    // reloc_entry is now the first entry (IMAGE_BASE_RELOCATION)
    auto reloc_entry = (base_dst + ((PIMAGE_DATA_DIRECTORY)reloc_dir)->VirtualAddress);
    while (((PIMAGE_BASE_RELOCATION)reloc_entry)->SizeOfBlock) {
      // VA for the current relocation block
      auto reloc_block = (base_dst + ((PIMAGE_BASE_RELOCATION)reloc_entry)->VirtualAddress);
      auto nrelocations = (((PIMAGE_BASE_RELOCATION)reloc_entry)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
      // entry of the current relocation block
      auto reloc = reloc_entry + sizeof(IMAGE_BASE_RELOCATION);
      while (nrelocations--) {
        // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
        // we dont use a switch statement to avoid the compiler building a jump table
        // which would not be very position independent!
        if (((PIMAGE_RELOC)reloc)->type == IMAGE_REL_BASED_DIR64)
          *(ULONG_PTR *)(reloc_block + ((PIMAGE_RELOC)reloc)->offset) += base_delta;
        else if (((PIMAGE_RELOC)reloc)->type == IMAGE_REL_BASED_HIGHLOW)
          *(DWORD *)(reloc_block + ((PIMAGE_RELOC)reloc)->offset) += (DWORD)base_delta;
        else if (((PIMAGE_RELOC)reloc)->type == IMAGE_REL_BASED_HIGH)
          *(WORD *)(reloc_block + ((PIMAGE_RELOC)reloc)->offset) += HIWORD(base_delta);
        else if (((PIMAGE_RELOC)reloc)->type == IMAGE_REL_BASED_LOW)
          *(WORD *)(reloc_block + ((PIMAGE_RELOC)reloc)->offset) += LOWORD(base_delta);

        reloc += sizeof(IMAGE_RELOC);
      }

      // get the next entry in the relocation directory
      reloc_entry = reloc_entry + ((PIMAGE_BASE_RELOCATION)reloc_entry)->SizeOfBlock;
    }
  }

  // Call entrypoint

  auto entrypoint = (base_dst + ((PIMAGE_NT_HEADERS)header)->OptionalHeader.AddressOfEntryPoint);
  auto current_process = (HANDLE)-1;
  pNtFlushInstructionCache(current_process, NULL, 0);
  ((_DllMain)entrypoint)((HINSTANCE)base_dst, DLL_PROCESS_ATTACH, parameter);
  return entrypoint;
}

extern "C" HINSTANCE hAppInstance = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
  BOOL bReturnValue = TRUE;
  switch (dwReason) {
    case DLL_PROCESS_ATTACH:
      CreateThread(0, 0, (LPTHREAD_START_ROUTINE)example, 0, 0, 0);
      break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
      break;
  }
  return bReturnValue;
}