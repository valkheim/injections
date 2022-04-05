#include <stdio.h>
#include <tchar.h>
#include <windows.h>

extern "C" __declspec(dllexport) bool example()
{
  MessageBoxA(NULL, "example", "example", NULL);
  return true;
}

extern "C" __declspec(dllexport) int ret(int value) { return value; }

BOOL APIENTRY DllMain(HMODULE hModule, DWORD nReason, LPVOID lpReserved)
{
  TCHAR pszMessage[1024] = {0};
  _stprintf_s(pszMessage, _T("GetCurrentProcessId() %d, hModule 0x%p, nReason %d\r\n"), GetCurrentProcessId(), hModule, nReason);
  OutputDebugString(pszMessage);

  switch (nReason) {
    case DLL_PROCESS_ATTACH:
      // MessageBoxA(NULL, "DLL_PROCESS_ATTACH", "DLL_PROCESS_ATTACH", NULL);
      break;

    case DLL_THREAD_ATTACH:
      // MessageBoxA(NULL, "DLL_THREAD_ATTACH", "DLL_THREAD_ATTACH", NULL);
      break;

    case DLL_THREAD_DETACH:
      // MessageBoxA(NULL, "DLL_THREAD_DETACH", "DLL_THREAD_DETACH", NULL);
      break;

    case DLL_PROCESS_DETACH:
      // MessageBoxA(NULL, "DLL_PROCESS_DETACH", "DLL_PROCESS_DETACH", NULL);
      break;
  }
  return TRUE;
}