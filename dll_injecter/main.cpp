#include "dll_inject.h"
#include "ulib.h"

// https://attack.mitre.org/techniques/T1055/001/
int main(int argc, char *argv[])
{
  if (argc != 3) {
    ::ul::error("inject.exe <dll path> <process name>");
    return EXIT_FAILURE;
  }

  auto dll_path = std::string{argv[1]};
  auto process_name = std::string{argv[2]};
  auto found = ::ul::with_process_using_wts(process_name, [&](::ul::Process const &process) -> ::ul::walk_t {
    auto pid = process.pid;
    printf("Injecting DLL %s to PID: %ld\n", dll_path.c_str(), pid);
    if (inject_using_reflective_dll(std::move(dll_path), pid) == false) {
      ::ul::error("Cannot inject DLL using the CreateRemoteThread technique");
      return ::ul::walk_t::WALK_STOP;
    }

    /*if (inject_dll_using_createremotethread(std::move(dll_path), pid) == false) {
      ::ul::error("Cannot inject DLL using the CreateRemoteThread technique");
      return ::ul::walk_t::WALK_STOP;
    }*/

    return ::ul::walk_t::WALK_STOP;
  });

  if (!found) {
    ::ul::error("Process " + process_name + " not found");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}