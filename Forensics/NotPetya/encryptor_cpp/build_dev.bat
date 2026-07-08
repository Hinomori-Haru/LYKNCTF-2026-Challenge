@echo off
REM === DEV build ===
cl /nologo /EHsc /O2 /std:c++17 /DYUNEKO_DEV main.cpp /Fe:encryptor_dev.exe /link bcrypt.lib
if %ERRORLEVEL% EQU 0 (
    echo.
    echo OK -^> encryptor_dev.exe
) else (
    echo.
    echo BUILD FAILED.
)
