@echo off
rem One-click wrapper around the noninteractive quality baseline. The Python
rem runner owns the check list and exit status; this wrapper only adds the
rem final pause that is useful when the file is opened by double-clicking.
cd /d "%~dp0"
if not exist "..\.venv\Scripts\python.exe" (
    echo Python virtual environment not found at ..\.venv\
    echo Run the setup steps in README.md first, then try again.
    pause
    exit /b 1
)

..\.venv\Scripts\python.exe tooling\verify.py
set RESULT=%ERRORLEVEL%
pause
exit /b %RESULT%
