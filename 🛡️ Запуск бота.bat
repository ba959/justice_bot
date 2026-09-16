@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Justice Bot
python bot.py
pause