@echo off
setlocal

REM Determine where we're running from
set "EXEDIR=%~dp0"

REM Check if fipsmodule.cnf already exists
if exist "%EXEDIR%fipsmodule.cnf" (
    echo fipsmodule.cnf already exists.
    goto :EOF
)

echo Running fipsinstall to initialize FIPS module...

"%EXEDIR%openssl.exe" fipsinstall ^
    -module "%EXEDIR%fips.dll" ^
    -out "%EXEDIR%fipsmodule.cnf" ^
    -provider_name fips ^
    -mac_name HMAC ^
    -macopt digest:SHA256


if errorlevel 1 (
    echo FIPS install failed.
    pause
    exit /b 1
)

echo FIPS install completed successfully.
pause
