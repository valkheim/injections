#include <windows.h>

extern "C" __declspec(dllexport) bool example()
{
  MessageBoxA(NULL, "example", "example", NULL);
  return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      MessageBoxA(NULL, "DLL_PROCESS_ATTACH", "DLL_PROCESS_ATTACH", NULL);
      break;

    case DLL_THREAD_ATTACH:
      MessageBoxA(NULL, "DLL_THREAD_ATTACH", "DLL_THREAD_ATTACH", NULL);
      break;

    case DLL_THREAD_DETACH:
      MessageBoxA(NULL, "DLL_THREAD_DETACH", "DLL_THREAD_DETACH", NULL);
      break;

    case DLL_PROCESS_DETACH:
      MessageBoxA(NULL, "DLL_PROCESS_DETACH", "DLL_PROCESS_DETACH", NULL);
      break;
  }

  return TRUE;
}