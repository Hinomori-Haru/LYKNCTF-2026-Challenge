@echo off
REM === RELEASE ===
cl /nologo /EHsc /O2 /std:c++17 main.cpp /Fe:encryptor.exe /link bcrypt.lib
if %ERRORLEVEL% EQU 0 (
    echo.
    echo OK -^> encryptor.exe
) else (
    echo.
    echo BUILD FAILED.
)
