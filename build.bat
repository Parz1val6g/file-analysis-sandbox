@echo off
REM build.bat — One-click build for sandbox_engine.exe (Windows)
REM Uses TCC (Tiny C Compiler) — portable, zero-install.
REM Download TCC from: https://download.savannah.gnu.org/releases/tinycc/

set TCC=%TEMP%\tcc\tcc\tcc.exe
set SRCDIR=sandbox\src
set TESTDIR=sandbox\tests
set ENGINE=sandbox\sandbox_engine.exe
set TESTER=sandbox\test_runner.exe

if not exist "%TCC%" (
    echo TCC not found. Downloading...
    powershell -Command "Invoke-WebRequest -Uri 'https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27-win64-bin.zip' -OutFile '%TEMP%\tcc.zip' -UseBasicParsing" 2>nul
    powershell -Command "Expand-Archive -Path '%TEMP%\tcc.zip' -DestinationPath '%TEMP%\tcc' -Force" 2>nul
    if not exist "%TCC%" (
        echo Failed to install TCC. Please install manually.
        exit /b 1
    )
)

echo Building sandbox_engine.exe ...
"%TCC%" -Wall %SRCDIR%\engine.c %SRCDIR%\sha256.c %SRCDIR%\json_builder.c %SRCDIR%\subprocess.c %SRCDIR%\validation.c %SRCDIR%\layer1_magic.c %SRCDIR%\layer2_clamav.c %SRCDIR%\layer3_sandbox.c -o %ENGINE%
if %ERRORLEVEL% neq 0 (
    echo Engine build FAILED
    exit /b 1
)
echo   Engine: OK

echo Building test_runner.exe ...
"%TCC%" -Wall %TESTDIR%\test_runner.c -o %TESTER%
if %ERRORLEVEL% neq 0 (
    echo Test runner build FAILED
    exit /b 1
)
echo   Test runner: OK

echo.
echo Running tests...
pushd sandbox
.\test_runner.exe
set TESTRC=%ERRORLEVEL%
popd

if "%TESTRC%"=="0" (
    echo All tests PASSED
) else (
    echo Tests FAILED: %TESTRC%
)
exit /b %TESTRC%
