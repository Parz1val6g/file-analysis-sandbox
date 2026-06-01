@echo off
REM build.bat — Windows build script for sandbox_engine.exe
REM Uses TCC (Tiny C Compiler) since it's zero-install portable.

set TCC=%TEMP%\tcc\tcc\tcc.exe
set SRC=sandbox\src
set OUT=sandbox\sandbox_engine.exe

if not exist "%TCC%" (
    echo TCC not found — please download from https://download.savannah.gnu.org/releases/tinycc/
    exit /b 1
)

echo Building sandbox_engine.exe ...
"%TCC%" -Wall %SRC%\engine.c %SRC%\sha256.c %SRC%\json_builder.c %SRC%\subprocess.c %SRC%\validation.c %SRC%\layer1_magic.c %SRC%\layer2_clamav.c %SRC%\layer3_sandbox.c -o %OUT%

if %ERRORLEVEL% equ 0 (
    echo Build successful: %OUT%
) else (
    echo Build FAILED
    exit /b 1
)
