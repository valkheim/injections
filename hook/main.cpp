#include "Windows.h"
#include "stdio.h"
#include "ulib.h"

void MyMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);
::ul::x64::Hook68* my_hook = nullptr;

void MyMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
  my_hook->unhook();
  MessageBoxA(NULL, "hooked!", "", MB_OK);
  my_hook->hook();
}

int main(int argc, char* argv[])
{
  auto hook_location = GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");

  my_hook = new ::ul::x64::Hook68((FARPROC)hook_location, (PROC)MyMessageBox);

  MessageBoxA(NULL, "1/3", "", MB_OK);
  my_hook->hook();
  MessageBoxA(NULL, "2/3", "", MB_OK);
  my_hook->unhook();
  MessageBoxA(NULL, "3/3", "", MB_OK);

  return 0;
}