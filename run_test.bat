@echo off
set "IDADIR=C:\Program Files\IDA Professional 9.2"
set "PATH=%IDADIR%;%PATH%"
set "PYTHONPATH="
set "PYTHONHOME="
set "PIP_PYTHON="
"%IDADIR%\idat.exe" -A -Shello_ida.py test_target.exe
