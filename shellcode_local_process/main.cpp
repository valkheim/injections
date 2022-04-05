#include <windows.h>

#include "ulib.h"

int main()
{
#if _WIN64
  constexpr uint8_t shellcode[206] = ul::shellcodes::x64::pop_calc;
#else
  constexpr uint8_t shellcode[201] = ul::shellcodes::x86::pop_calc;
#endif

  void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memcpy(exec, shellcode, sizeof(shellcode));
  ((void (*)())exec)();
}