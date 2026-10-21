@echo off
rem dsh-rea-toolkit bootstrap entry (Windows).
rem Prefers DSH_REA_NODE / system node; prints setup guidance when absent.
setlocal
set "SCRIPT_DIR=%~dp0"

where node >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  node "%SCRIPT_DIR%install-tools.mjs" %*
  exit /b %ERRORLEVEL%
)

if exist "%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe" (
  "%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe" "%SCRIPT_DIR%install-tools.mjs" %*
  exit /b %ERRORLEVEL%
)

echo Node.js 22.19+/24.11+/26+ is required but was not found.
echo Install Node.js from https://nodejs.org , then re-run this script.
exit /b 1
