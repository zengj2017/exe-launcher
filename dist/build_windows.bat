@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

echo ============================================================
echo       launcher.exe Windows 一键编译脚本
echo ============================================================
echo.

:: 检查 Python 是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Python，请先安装 Python 3.8+
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/4] 检测到 Python:
python --version
echo.

:: 安装依赖
echo [2/4] 正在安装依赖包...
pip install pyinstaller pycryptodome --quiet
if errorlevel 1 (
    echo [错误] 依赖安装失败，请检查网络连接
    pause
    exit /b 1
)
echo      依赖安装完成
echo.

:: 选择版本
echo [3/4] 请选择要编译的版本:
echo      1. V1 - 永久密钥版本 (launcher.exe)
echo      2. V2 - 时效性密钥版本 (launcher_v2.exe)
echo      3. 同时编译两个版本
echo.
set /p choice="请输入选择 (1/2/3): "

echo.
echo [4/4] 开始编译...
echo.

if "%choice%"=="1" goto build_v1
if "%choice%"=="2" goto build_v2
if "%choice%"=="3" goto build_both
goto build_both

:build_v1
echo 正在编译 V1 版本...
pyinstaller --onefile --windowed --name=launcher --clean launcher.py
if errorlevel 1 (
    echo [错误] V1 编译失败
    pause
    exit /b 1
)
echo [成功] V1 编译完成: dist\launcher.exe
goto done

:build_v2
echo 正在编译 V2 版本...
pyinstaller --onefile --windowed --name=launcher_v2 --clean launcher_v2.py
if errorlevel 1 (
    echo [错误] V2 编译失败
    pause
    exit /b 1
)
echo [成功] V2 编译完成: dist\launcher_v2.exe
goto done

:build_both
echo 正在编译 V1 版本...
pyinstaller --onefile --windowed --name=launcher --clean launcher.py
if errorlevel 1 (
    echo [警告] V1 编译失败
) else (
    echo [成功] V1 编译完成
)
echo.
echo 正在编译 V2 版本...
pyinstaller --onefile --windowed --name=launcher_v2 --clean launcher_v2.py
if errorlevel 1 (
    echo [警告] V2 编译失败
) else (
    echo [成功] V2 编译完成
)
goto done

:done
echo.
echo ============================================================
echo                    编译完成！
echo ============================================================
echo.
echo 生成的文件位置:
if exist "dist\launcher.exe" echo   - dist\launcher.exe (V1 永久密钥版)
if exist "dist\launcher_v2.exe" echo   - dist\launcher_v2.exe (V2 时效性版)
echo.
echo 使用说明:
echo   1. 将生成的 .exe 文件与加密后的 encrypted_app.dat 放在同一目录
echo   2. 运行 .exe 文件，输入密钥即可使用
echo.
pause
