@echo off
:: Simple launcher for the Python installer
python "%~dp0install.py" %*
if errorlevel 1 pause
