@echo off
REM find_ip.bat - launcher for find_ip.ps1 (bypasses PowerShell Execution Policy)
REM   find_ip.bat
REM   find_ip.bat -Subnet 192.168.1.0/24
REM   find_ip.bat -Mac AA-BB-CC-DD-EE-FF
REM   find_ip.bat -Name laptop -Csv result.csv

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0find_ip.ps1" %*
if "%~1"=="" pause
