@echo off
chcp 65001 >nul
title BKI Portal - AI Offline Mode

echo ================================================
echo   BKI Network Portal - AI آفلاین (Qwen2.5:7b)
echo ================================================
echo.

:: ---- تنظیمات AI ----
set AI_PROVIDER=openai
set AI_BASE_URL=http://localhost:11434/v1
set AI_MODEL=qwen2.5:7b

:: ---- بررسی نصب Ollama ----
where ollama >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Ollama نصب نیست.
    echo.
    echo لطفاً از لینک زیر دانلود و نصب کنید:
    echo   https://ollama.com/download/OllamaSetup.exe
    echo.
    echo بعد از نصب، این فایل را دوباره اجرا کنید.
    echo.
    pause
    start https://ollama.com/download/OllamaSetup.exe
    exit /b 1
)

:: ---- راه‌اندازی Ollama ----
tasklist /FI "IMAGENAME eq ollama.exe" 2>NUL | find /I /N "ollama.exe" >NUL
if %errorlevel% neq 0 (
    echo [*] Starting Ollama...
    start /B ollama serve
    timeout /t 3 /nobreak >nul
)

:: ---- بررسی و دانلود مدل ----
ollama list | findstr /I "qwen2.5:7b" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Downloading qwen2.5:7b  ~4.7GB, please wait...
    ollama pull qwen2.5:7b
    if %errorlevel% neq 0 (
        echo [!] Download failed. Check your internet connection.
        pause
        exit /b 1
    )
)

echo.
echo [OK] Ollama: http://localhost:11434
echo [OK] AI Model: %AI_MODEL%
echo.
echo [*] Starting BKI Portal...
echo.

python server_database.py
pause
