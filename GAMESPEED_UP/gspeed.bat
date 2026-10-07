@echo off
setlocal
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
title TAB GameSpeed
set "TAB_PYTHON="
py -3 -c "import struct,sys; sys.exit(0 if sys.version_info >= (3,7) and struct.calcsize('P') == 8 else 1)" >nul 2>&1
if not errorlevel 1 set "TAB_PYTHON=py -3"
if defined TAB_PYTHON goto run
python -c "import struct,sys; sys.exit(0 if sys.version_info >= (3,7) and struct.calcsize('P') == 8 else 1)" >nul 2>&1
if not errorlevel 1 set "TAB_PYTHON=python"
if defined TAB_PYTHON goto run
echo [TAB GameSpeed] Python 3.7+ 64-bit was not found.
echo Install 64-bit Python and enable the Python launcher or add Python to PATH.
pause
exit /b 1
:run
echo [TAB GameSpeed]  Launcher
echo   Start the game and load into a match first, then run this tool.
echo   In the window: type a number (2/3/5/8/12) to speed up, 0 for 1x, q to quit.
echo.
%TAB_PYTHON% "%~dp0tab_gspeed.py" %*
echo.
echo --- exited ---
pause
