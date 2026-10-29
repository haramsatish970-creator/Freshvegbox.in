@echo off
setlocal
cd /d "%~dp0"
python server.py --setup-admin
if errorlevel 1 pause
