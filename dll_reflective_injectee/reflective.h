#pragma once

#include <windows.h>
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)
#pragma intrinsic(_rotr)

typedef BOOL(WINAPI* _DllMain)(HINSTANCE, DWORD, LPVOID);
typedef HMODULE(WINAPI* _LoadLibrary)(LPCSTR);
typedef FARPROC(WINAPI* _GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* _VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(NTAPI* _NtFlushInstructionCache)(HANDLE, PVOID, ULONG);

#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D

#define LOADLIBRARYA_HASH				0xEC0E4E8E
#define GETPROCADDRESS_HASH				0x7C0DFCAA
#define VIRTUALALLOC_HASH				0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH	0x534C0AB8