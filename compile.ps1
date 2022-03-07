function CheckLastExitCode {
    param ([int[]]$SuccessCodes = @(0))

    if (!$?) {
        Write-Host "Last CMD failed" -ForegroundColor Red
        exit
    }

    if ($SuccessCodes -notcontains $LastExitCode) {
        Write-Host "EXE RETURNED EXIT CODE $LastExitCode" -ForegroundColor Red
        exit
    } 
    
}

# Prepare build
cmake -G "Visual Studio 16 2019" -A Win32 -S . -B build/x86
# cmake -G "Ninja" -A x86 -S . -B build/x86
cmake -G "Visual Studio 16 2019" -A x64 -S . -B build/x64
# cmake -G "Ninja" -A x64  -S . -B build/x64

# Build
cmake --build build/x86 --config Debug
cmake --build build/x64 --config Debug
CheckLastExitCode

# cmake --build build/x86 --config Release
# cmake --build build/x64 --config Release

# Format
# cmake --build build/x86 --target clangformat
cmake --build build/x64 --target clangformat
CheckLastExitCode

# Test
.\build\x86\ulib\test\Debug\ulib_test.exe
.\build\x64\ulib\test\Debug\ulib_test.exe