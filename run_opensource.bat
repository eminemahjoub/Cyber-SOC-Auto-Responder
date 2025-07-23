@echo off
title Streamlined Cyber-SOC Auto-Responder

echo.
echo   ####   #####  #   # #####   ####### #    #  
echo      #  #     #  # #  #    #  #     #  #  #  
echo      #  #     #   #   #    #  #     #   #   
echo      #  #     #   #   #####   #     #   #   
echo      #  #     #   #   #    #  #     #   #   
echo #    #  #     #   #   #    #  #     #   #   
echo  ####    #####    #   # # #   #######   #   
echo.
echo ======================================================================
echo 🌟 STREAMLINED CYBER-SOC AUTO-RESPONDER
echo ======================================================================
echo 🔧 Core Stack: Wazuh + OpenVAS
echo 🦠 Enhancement: VirusTotal Threat Intelligence
echo.

echo [INFO] Starting Streamlined Cyber-SOC Auto-Responder...
echo [INFO] Press Ctrl+C to stop the system
echo.

REM Set default environment variables for open-source tools
if "%WAZUH_URL%"=="" set WAZUH_URL=https://localhost:55000
if "%WAZUH_USERNAME%"=="" set WAZUH_USERNAME=wazuh
if "%WAZUH_PASSWORD%"=="" set WAZUH_PASSWORD=wazuh

if "%OPENVAS_URL%"=="" set OPENVAS_URL=https://localhost:9390
if "%OPENVAS_USERNAME%"=="" set OPENVAS_USERNAME=admin
if "%OPENVAS_PASSWORD%"=="" set OPENVAS_PASSWORD=admin

if "%VIRUSTOTAL_API_KEY%"=="" set VIRUSTOTAL_API_KEY=f5819e00da02b057ec600673a825e42bbc5dcb7066c79a8ac7e352c9b6fd1979

if "%POLL_INTERVAL%"=="" set POLL_INTERVAL=30
if "%MAX_CONCURRENT_ALERTS%"=="" set MAX_CONCURRENT_ALERTS=5
if "%VULNERABILITY_SCAN_THRESHOLD%"=="" set VULNERABILITY_SCAN_THRESHOLD=7.0
if "%HIGH_PRIORITY_THRESHOLD%"=="" set HIGH_PRIORITY_THRESHOLD=8.0
if "%IOC_ANALYSIS_THRESHOLD%"=="" set IOC_ANALYSIS_THRESHOLD=6.0

echo [INFO] Streamlined SOC Configuration:
echo   - Wazuh SIEM: %WAZUH_URL%
echo   - OpenVAS Scanner: %OPENVAS_URL%
echo   - VirusTotal Enhancement: API Key Configured
echo   - Poll Interval: %POLL_INTERVAL% seconds
echo   - Vulnerability Scan Threshold: %VULNERABILITY_SCAN_THRESHOLD%
echo   - IOC Analysis Threshold: %IOC_ANALYSIS_THRESHOLD%
echo.

echo [INFO] Installing required dependencies...
pip install requests aiohttp

echo [INFO] Launching streamlined SOC system...
python opensource_production.py

echo.
echo [INFO] Streamlined Cyber-SOC Auto-Responder has stopped.
pause 