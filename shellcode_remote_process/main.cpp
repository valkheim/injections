#include "inject.h"

int main(int argc, char** argv)
{
  // Try with C:\Windows\system32\notepad.exe or C:\Windows\SysWOW64\notepad.exe
  auto process_name = std::string{argv[1]};
  auto technique = std::string{argv[2]};

  (void)::ul::with_process_using_wts(process_name, [&](::ul::Process const& process) -> ::ul::walk_t {
    auto pid = process.pid;
    ::ul::info(std::format("Injecting to {} ({}) using {} technique", process_name, pid, technique));
    if (technique == "inject") inject_thread(pid);
    if (technique == "hijack") hijack_thread(process_name);
    if (technique == "apc_queue") hijack_thread(process_name);
    if (technique == "early_apc_queue") hijack_thread(process_name);
    if (technique == "memory_view") memory_view(pid);

    return ::ul::walk_t::WALK_STOP;
  });
}