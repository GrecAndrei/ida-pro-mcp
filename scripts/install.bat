@echo off
setlocal enabledelayedexpansion
title IDA Pro MCP Auto-Installer

echo ========================================================
echo           IDA Pro MCP Auto-Installer (v1.0.0a1)
echo ========================================================

set "REPO=GrecAndrei/ida-pro-mcp"
set "VERSION=1.0.0a1"
set "TAG=v1.0.0a1"
set "WHEEL_URL=https://github.com/%REPO%/releases/download/%TAG%/ida_pro_mcp-%VERSION%-py3-none-any.whl"

:: 1. Find Python (3.11+)
set "PYTHON_BIN="
where py >nul 2>&1
if %ERRORLEVEL% equ 0 (
    py -3 -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
    if !ERRORLEVEL! equ 0 set "PYTHON_BIN=py -3"
)

if "%PYTHON_BIN%"=="" (
    where python >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        python -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
        if !ERRORLEVEL! equ 0 set "PYTHON_BIN=python"
    )
)

if "%PYTHON_BIN%"=="" (
    echo [-] Error: Python 3.11 or newer is required but was not found.
    echo     Please install Python 3.11+ from https://www.python.org/
    echo     and ensure "Add Python to PATH" is checked.
    pause
    exit /b 1
)

echo [*] Using Python: %PYTHON_BIN%

:: 2. Determine install root
if "%LOCALAPPDATA%"=="" (
    set "INSTALL_ROOT=%USERPROFILE%\.local\share\ida-pro-mcp"
) else (
    set "INSTALL_ROOT=%LOCALAPPDATA%\ida-pro-mcp"
)
echo [*] Install root: %INSTALL_ROOT%
if not exist "%INSTALL_ROOT%" mkdir "%INSTALL_ROOT%"

:: 3. Create isolated virtual environment
set "VENV_DIR=%INSTALL_ROOT%\.venv"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"
set "VENV_PIP=%VENV_DIR%\Scripts\pip.exe"

if not exist "%VENV_PY%" (
    echo [*] Creating isolated virtual environment in %VENV_DIR%...
    %PYTHON_BIN% -m venv "%VENV_DIR%"
    if !ERRORLEVEL! neq 0 (
        echo [-] Error: Failed to create virtual environment.
        pause
        exit /b 1
    )
)

:: 4. Install / Upgrade IDA Pro MCP
echo [*] Installing/updating IDA Pro MCP (%VERSION%)...
"%VENV_PY%" -m pip install --upgrade pip --quiet
"%VENV_PIP%" install --upgrade "%WHEEL_URL%" --quiet
if %ERRORLEVEL% neq 0 (
    echo [-] Error: Failed to install package from %WHEEL_URL%
    pause
    exit /b 1
)

:: 5. Execute automated configuration
echo [*] Auto-detecting IDA Pro installations, configuring MCP clients, and installing skills...
"%VENV_PY%" -m ida_pro_mcp.installer.main --auto %*
if %ERRORLEVEL% neq 0 (
    echo [-] Error: Configuration step returned an error.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo [OK] IDA Pro MCP successfully installed and configured!
echo ========================================================
echo You can now use IDA Pro MCP in your AI coding agents.
pause
