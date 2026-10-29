@echo off
REM Build the IL dumper DLL and the injector (x64).
REM Run from an "x64 Native Tools Command Prompt for VS".

cl /nologo /LD /EHsc /O2 /DUNICODE /D_UNICODE dumper.cpp /Fe:dumper.dll
if errorlevel 1 goto :err

cl /nologo /EHsc /O2 inject.cpp /Fe:inject.exe
if errorlevel 1 goto :err

echo.
echo Built dumper.dll and inject.exe
goto :eof

:err
echo BUILD FAILED
exit /b 1
