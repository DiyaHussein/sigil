@echo off
title Sigil
cd /d "%~dp0"
if exist .env (for /f "usebackq tokens=1,* delims==" %%a in (".env") do set "%%a=%%b")
echo Starting Sigil on http://127.0.0.1:8090/app/
python -m uvicorn sigil.main:app --host 127.0.0.1 --port 8090 --reload
