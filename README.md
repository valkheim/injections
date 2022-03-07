# Red

## Compile

```console
> powershell.exe -ExecutionPolicy Bypass -File .\compile.ps1
```

## Test

```console
> .\build\x86\ulib\test\Debug\ulib_test.exe
Running main() from .\third_party\googletest\src\gtest_main.cc
[==========] Running 7 tests from 4 test suites.
[----------] Global test environment set-up.
[----------] 1 test from modules
[ RUN      ] modules.test_modules_found
[       OK ] modules.test_modules_found (0 ms)
[----------] 1 test from modules (3 ms total)

[----------] 4 tests from processes
[ RUN      ] processes.test_using_enumprocess
[       OK ] processes.test_using_enumprocess (2 ms)
[ RUN      ] processes.test_using_toolhelp
[       OK ] processes.test_using_toolhelp (4 ms)
[ RUN      ] processes.test_using_wts
[       OK ] processes.test_using_wts (5 ms)
[ RUN      ] processes.test_compatibility
[       OK ] processes.test_compatibility (12 ms)
[----------] 4 tests from processes (39 ms total)

[----------] 1 test from shellcodes
[ RUN      ] shellcodes.test_sizes
[       OK ] shellcodes.test_sizes (0 ms)
[----------] 1 test from shellcodes (4 ms total)

[----------] 1 test from version
[ RUN      ] version.test_version
[       OK ] version.test_version (0 ms)
[----------] 1 test from version (3 ms total)

[----------] Global test environment tear-down
[==========] 7 tests from 4 test suites ran. (73 ms total)
[  PASSED  ] 7 tests.
```