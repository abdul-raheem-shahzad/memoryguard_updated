@echo off
REM MemoryGuard one-click start for Windows
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py) || (set PY=python)
echo Installing requirements...
%PY% -m pip install -q -r requirements.txt
if errorlevel 1 (echo Install failed. Is Python installed and on PATH? & pause & exit /b 1)

REM ONE admin key, always the same. It lives in "MemoryGuard admin key.txt" in this
REM folder. The server is started with it, so even a fresh database recreates this
REM same key instead of inventing a new one. MOVE THAT FILE OUT before sharing the folder.
set "KEYFILE=%~dp0MemoryGuard admin key.txt"
set "MG_ADMIN_KEY="
if exist "%KEYFILE%" for /f "usebackq delims=" %%L in (`findstr /b /c:"mg_adm_" "%KEYFILE%"`) do set "MG_ADMIN_KEY=%%L"
echo.
if defined MG_ADMIN_KEY goto havekey
REM First start on this computer: create the admin key and save it in the key file.
%PY% -m app.manage bootstrap --save "%KEYFILE%"
if exist "%KEYFILE%" for /f "usebackq delims=" %%L in (`findstr /b /c:"mg_adm_" "%KEYFILE%"`) do set "MG_ADMIN_KEY=%%L"
if defined MG_ADMIN_KEY (echo Your admin key is in "MemoryGuard admin key.txt". It never changes.) else (echo Could not create the admin key file. Ask whoever sent you MemoryGuard.)
goto start
:havekey
echo Using your admin key from "MemoryGuard admin key.txt" (it never changes).
:start
echo.

echo Starting server in a new window...
start "MemoryGuard server" cmd /k "%PY% -m uvicorn app.main:app --port 8000"
timeout /t 6 /nobreak >nul

if exist seeded.flag goto open
if not defined MG_ADMIN_KEY set /p "MG_ADMIN_KEY=Paste the admin key to load demo data (or press Enter to skip): "
if not defined MG_ADMIN_KEY goto open
REM seed.py reads the key from the environment, so it never appears on a command line
%PY% demo\seed.py http://localhost:8000 && echo done> seeded.flag

:open
set "MG_ADMIN_KEY="
start http://localhost:8000
echo.
echo Dashboard: http://localhost:8000   API docs: http://localhost:8000/docs
echo Sign in with the key in "MemoryGuard admin key.txt" in this folder.
echo Close the "MemoryGuard server" window to stop.
pause
