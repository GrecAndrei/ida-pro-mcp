@echo off
set "IDADIR=C:\Program Files\IDA Professional 9.2"
set "PATH=%IDADIR%;%PATH%"
set "PYTHONHOME="
set "PYTHONPATH="
set "IDA_MCP_PORT=13337"
echo Starting IDA...
"%IDADIR%\ida.exe" -A -S"C:\Users\Alexander\Downloads\ida-pro-mcp\src\ida_pro_mcp\server_script.py" "C:\Users\Alexander\Downloads\ida-pro-mcp\test_target.exe"
echo IDA Finished with code %ERRORLEVEL%