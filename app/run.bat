@echo off
cd /d "%~dp0"

if not exist "..\.venv\Scripts\python.exe" (
    echo Python virtual environment not found at ..\.venv\
    echo Run the setup steps in README.md first, then try again.
    pause
    exit /b 1
)

if not exist "packages\frontend\node_modules" (
    echo Frontend dependencies not installed yet.
    echo Run "npm install" inside the packages\frontend\ folder first, then try again.
    pause
    exit /b 1
)

rem RedactLens looks for the "qwen3-coder:30b" model by default. Set this to whatever
rem you've actually pulled (check with "ollama list") so the "local AI"
rem toggle in the UI works instead of always showing "not detected".
if "%REDACTLENS_OLLAMA_MODEL%"=="" set REDACTLENS_OLLAMA_MODEL=qwen3-coder:30b

echo Starting the RedactLens API and frontend in their own windows...
echo Using Ollama model: %REDACTLENS_OLLAMA_MODEL%
start "RedactLens API (127.0.0.1:8000)" cmd /k "set REDACTLENS_OLLAMA_MODEL=%REDACTLENS_OLLAMA_MODEL% && ..\.venv\Scripts\python.exe -m redactlens_api"
start "RedactLens Frontend (localhost:5173)" cmd /k "cd packages\frontend && npm run dev"

timeout /t 4 /nobreak >nul
start http://localhost:5173

echo Both servers are starting in their own windows.
echo Close those windows (or press Ctrl+C in each) to stop them.
echo.
echo (This window can be closed now -- it's done its job.)
pause
