@echo off
echo Cleaning up old build...
taskkill /f /im YaraXGUI.exe 2>nul
if exist "dist\YaraXGUI.exe" del /f "dist\YaraXGUI.exe" 2>nul
if exist "build" rmdir /s /q "build" 2>nul

echo Building YaraXGUI executable...
R:/YaraXGUI_Qt/YaraXGUI/.qtcreator/Python_3_13_7venv/Scripts/python.exe -m PyInstaller yaraxgui.spec

if %errorlevel%==0 (
    echo.
    echo ✅ Build completed successfully!
    echo Executable created at: dist\YaraXGUI.exe
) else (
    echo.
    echo ❌ Build failed with error code %errorlevel%
)
pause