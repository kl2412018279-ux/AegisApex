@echo off
rem AegisApex agent - double-click to start on Windows.
rem First run: asks for your Supabase URL and service_role key and saves them
rem to agent\.env (never committed). Later runs start straight away.
setlocal
cd /d "%~dp0"
title AegisApex agent

where python >nul 2>nul
if errorlevel 1 goto nopython

if exist .env goto install

echo.
echo === First-time setup ===
echo Find these in Supabase: Project Settings ^> API.
echo.
:askurl
set "SUPA_URL="
set /p "SUPA_URL=Paste your Supabase Project URL (https://....supabase.co): "
echo %SUPA_URL%| findstr /b /c:"https://" >nul
if errorlevel 1 (
  echo   That does not start with https:// - try again.
  goto askurl
)
:askkey
set "SUPA_KEY="
set /p "SUPA_KEY=Paste your Supabase service_role key: "
if "%SUPA_KEY%"=="" goto askkey
> .env echo SUPABASE_URL=%SUPA_URL%
>> .env echo SUPABASE_SERVICE_ROLE_KEY=%SUPA_KEY%
echo   Saved to agent\.env
set "SUPA_KEY="

:install
if not exist .venv\Scripts\python.exe (
  echo.
  echo Creating a private Python environment...
  python -m venv .venv
  if errorlevel 1 goto failed
)
echo Installing / checking requirements...
.venv\Scripts\python.exe -m pip install --disable-pip-version-check -q -r requirements.txt
if errorlevel 1 goto failed

echo.
echo Starting the agent. Keep this window open. Press Ctrl+C to stop.
echo.
.venv\Scripts\python.exe worker.py
echo.
echo The agent stopped.
pause
exit /b 0

:nopython
echo Python is not installed (or not on PATH).
echo Install Python 3.12 from python.org and tick "Add python.exe to PATH",
echo then double-click this file again.
start "" https://www.python.org/downloads/
pause
exit /b 1

:failed
echo.
echo Setup failed - copy the red text above and send it for help.
pause
exit /b 1
