@echo off
title WebFuzzer - Security Testing Tool
color 0A

echo.
echo ===============================
echo      Web Fuzzer Interface
echo ===============================
echo.

if exist web_input.json (
    echo Found web input file, running scan...
    python web_fuzzer.py
    echo.
    echo ✅ Scan completed! Opening report...
    start report.html
) else (
    echo No web input found. Running interactive mode...
    python Fuzzer.py
)

pause