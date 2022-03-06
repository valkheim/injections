#include <windows.h>

#include "ulib.h"

void pop_calc()
{
  void *exec = VirtualAlloc(0, sizeof(ul::shellcodes::x86::pop_calc),
                            MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memcpy(exec, ul::shellcodes::x86::pop_calc,
         sizeof(ul::shellcodes::x86::pop_calc));
  ((void (*)())exec)();
}

int main() { pop_calc(); }